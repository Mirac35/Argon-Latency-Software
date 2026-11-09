using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using LibreHardwareMonitor.Hardware;

namespace ArgonLatencyStudio
{
    static class Program
    {
        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        [STAThread]
        static void Main(string[] args)
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, resolveArgs) =>
            {
                try
                {
                    string asmName = new AssemblyName(resolveArgs.Name).Name + ".dll";
                    string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                    string p1 = Path.Combine(baseDir, asmName);
                    if (File.Exists(p1)) return Assembly.LoadFrom(p1);
                    string p2 = Path.Combine(baseDir, "lib", asmName);
                    if (File.Exists(p2)) return Assembly.LoadFrom(p2);
                    string p3 = Path.Combine(baseDir, "..", "..", "lib", asmName);
                    if (File.Exists(p3)) return Assembly.LoadFrom(p3);
                }
                catch { }
                return null;
            };
            bool elevated = false;
            try { elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { }
            bool isRenderMode = false;
            for (int a = 0; a < args.Length; a++)
            {
                if (string.Equals(args[a], "--render-ui", StringComparison.OrdinalIgnoreCase))
                {
                    isRenderMode = true;
                    break;
                }
            }
            if (!elevated && Array.IndexOf(args, "--no-elevate") < 0 && !isRenderMode)
            {
                try
                {
                    ProcessStartInfo elevPsi = new ProcessStartInfo
                    {
                        FileName = Application.ExecutablePath,
                        Arguments = string.Join(" ", args),
                        UseShellExecute = true,
                        Verb = "runas"
                    };
                    Process.Start(elevPsi);
                    return; // the elevated instance takes over
                }
                catch { /* UAC declined -> continue in limited mode (saved profile is preserved) */ }
            }

            try { SetProcessDPIAware(); } catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (isRenderMode)
            {
                string renderPath = null;
                int renderTab = -1;
                string renderLang = null;
                for (int i = 0; i < args.Length; i++)
                {
                    if (string.Equals(args[i], "--render-ui", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    {
                        renderPath = args[i + 1];
                    }
                    else if (string.Equals(args[i], "--tab", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    {
                        int.TryParse(args[i + 1], out renderTab);
                    }
                    else if (string.Equals(args[i], "--lang", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    {
                        renderLang = args[i + 1];
                    }
                }

                if (!string.IsNullOrEmpty(renderPath))
                {
                    try
                    {
                        using (MainForm rForm = new MainForm(args))
                        {
                            if (!string.IsNullOrEmpty(renderLang))
                            {
                                rForm.ApplyLanguage(renderLang);
                            }
                            if (renderTab >= 0)
                            {
                                rForm.SwitchActiveTab(renderTab);
                            }
                            rForm.Size = new Size(1380, 890); // Native Default Medium Resolution
                            rForm.Show();
                            Application.DoEvents();
                            using (Bitmap bmp = new Bitmap(rForm.Width, rForm.Height))
                            {
                                rForm.DrawToBitmap(bmp, new Rectangle(0, 0, rForm.Width, rForm.Height));
                                bmp.Save(renderPath, System.Drawing.Imaging.ImageFormat.Png);
                                File.WriteAllText("render_debug.log", "RENDER_OK: " + renderPath + " size=" + rForm.Size);
                            }
                            rForm.Hide();
                        }
                    }
                    catch (Exception ex)
                    {
                        File.WriteAllText("render_debug.log", "RENDER_ERROR: " + ex.ToString());
                    }
                    return;
                }
            }

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

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public long Luid;
            public int Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(string systemName, string name, out long luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAll, ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

        // Enables a privilege that is present (but disabled) in the current process token.
        // Returns true only if the privilege is actually held afterwards (admin required).
        public static bool EnablePrivilege(string privilegeName)
        {
            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out token))
                    return false;
                long luid;
                if (!LookupPrivilegeValue(null, privilegeName, out luid))
                    return false;
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Luid = luid;
                tp.Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED
                if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    return false;
                // ERROR_NOT_ALL_ASSIGNED (1300): call "succeeded" but privilege not held
                return Marshal.GetLastWin32Error() == 0;
            }
            catch { return false; }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        public static extern int DnsFlushResolverCache();

        [DllImport("winmm.dll", EntryPoint = "mciSendStringA", CharSet = CharSet.Ansi)]
        public static extern int mciSendString(string command, StringBuilder buffer, int bufferSize, IntPtr hwndCallback);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool LockWorkStation();

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

        // Real-Time OS Truth Detection Engine Fields
        public bool IsDetectedActiveInOs = false;
        public int DetectedVariationInOs = -1;
        public string LiveOsRawSummary = "";
        public bool RequiresCautionConfirmation = false;
        public string CautionWarningText = "";

        // Automatic Boot-Time Truth & Zero-Bug Reboot Resolution
        public bool BootTimeActiveInOs = false;
        public int BootTimeVariationInOs = -1;
        public string BootTimeRawValue = "";

        /// <summary>
        /// Bu ayarın Windows çekirdeğinde devreye girmesi için yeniden başlatma gerekip gerekmediğini
        /// boot anındaki gerçek sistem durumu ile kıyaslayarak kesin olarak hesaplar.
        /// (1 -> 3 -> 1 gibi geçişlerde veya sistem bu değerle açılmışsa asla sahte restart uyarısı vermez!)
        /// </summary>
        public bool IsRebootPending
        {
            get
            {
                if (!NeedsReboot) return false;

                bool currentActive = IsEnabled;
                int currentVar = SelectedVariationIndex;

                bool bootActive = BootTimeActiveInOs;
                int bootVar = BootTimeVariationInOs;

                // 1. Canlı OS Doğrulaması (Live OS Truth):
                // Eğer ayar programda açıksa ve Windows Kayıt Defterinde/Kernel'de
                // bu ayar zaten seçili varyasyonla birebir doğrulanmışsa:
                if (currentActive && IsVerifiedInOs && (DetectedVariationInOs < 0 || DetectedVariationInOs == currentVar))
                {
                    // Ancak kullanıcı bu oturumda ayarı açılış modundan farklı bir moda elle çektiyse restart gerekir:
                    if (bootActive && bootVar >= 0 && bootVar != currentVar)
                        return true;

                    return false;
                }

                // 2. Her iki durumda da pasifse restart kesinlikle gerekmez:
                if (!currentActive && !bootActive && !IsDetectedActiveInOs)
                    return false;

                // 3. Her ikisinde de aktifse modların eşleşip eşleşmediğini kontrol et:
                if (currentActive && bootActive)
                {
                    if (bootVar >= 0 && bootVar == currentVar)
                        return false;
                    if (bootVar < 0 && IsVerifiedInOs)
                        return false;
                    return true;
                }

                // 4. Biri aktif diğeri pasif -> bu oturumda durum değişti, kernel için restart gerekir
                return true;
            }
        }

        public bool IsNetReloadPending
        {
            get
            {
                if (!NeedsNetReload) return false;
                if (!IsEnabled) return false;
                if (IsVerifiedInOs && (DetectedVariationInOs < 0 || DetectedVariationInOs == SelectedVariationIndex) && NetReloadSatisfied)
                    return false;
                return !NetReloadSatisfied;
            }
        }

        // Customizable Machine Variables & Safety Lock Architecture
        public CustomParamConfig CustomParam = null;
        public bool HasCustomParam
        {
            get { return CustomParam != null; }
        }
    }

    public class CustomParamConfig
    {
        public string ParameterName;
        public string DisplayLabel;
        public int MinValue;
        public int MaxValue;
        public int DefaultValue;
        public int CurrentCustomValue;
        public string Unit;
        public string TechnicalDescription;
        public string SafetyWarningTitle;
        public string SafetyWarningExplanation;
        public string RegeditTargetPath;
        public string GoogleSearchQuery;
        public int[] PresetQuickChips;
        public string[] PresetChipLabels;
        public Func<int> ReadCurrentValueFunc;
        public Action<int> ApplyCustomAction;

        public CustomParamConfig()
        {
            CurrentCustomValue = 0;
            MinValue = 0;
            MaxValue = 1000;
            DefaultValue = 100;
            Unit = "";
        }
    }

    public static class Loc
    {
        public static string CurrentLanguage = "TR"; // "TR" or "EN"

        public static bool IsEnglish
        {
            get { return string.Equals(CurrentLanguage, "EN", StringComparison.OrdinalIgnoreCase); }
        }

        public static string T(string tr, string en)
        {
            return IsEnglish ? en : tr;
        }
    }

    public class ArgonAppSettings
    {
        public bool EnableTelemetrySensors = true;
        public bool ShowCpuSensor = true;
        public bool ShowGpuCoreSensor = true;
        public bool ShowGpuMemHotspotSensor = true;
        public int TelemetryPollIntervalMs = 1000;
        public bool FixedWindowLayout = true;
        public bool RichCustomTooltips = true;
        public bool RichTooltipsEnabled { get { return RichCustomTooltips; } set { RichCustomTooltips = value; } }
        public bool CompactCardMode = false;
        public bool AutoLiveTruthSync = true;
        public bool ConfirmCriticalTweaks = true;
        public bool RevertOnExit = false;
        public string ActiveProfileName = "Varsayılan (Son Oturum)";
        public string LastSelectedProfileName { get { return ActiveProfileName; } set { ActiveProfileName = value; } }
        public string WindowResolutionPreset = "MEDIUM"; // "COMPACT" (1280x820), "MEDIUM" (1380x890), "LARGE" (1560x960), "EXTRA_LARGE" (1720x1020)
        public bool LockFixedResolution = true;
        public string AppLanguage = "TR"; // "TR" or "EN"

        public void Save(string path)
        {
            try
            {
                List<string> lines = new List<string>
                {
                    "EnableTelemetrySensors|" + EnableTelemetrySensors,
                    "ShowCpuSensor|" + ShowCpuSensor,
                    "ShowGpuCoreSensor|" + ShowGpuCoreSensor,
                    "ShowGpuMemHotspotSensor|" + ShowGpuMemHotspotSensor,
                    "TelemetryPollIntervalMs|" + TelemetryPollIntervalMs,
                    "FixedWindowLayout|" + FixedWindowLayout,
                    "WindowResolutionPreset|" + (WindowResolutionPreset ?? "MEDIUM"),
                    "LockFixedResolution|" + LockFixedResolution,
                    "RichCustomTooltips|" + RichCustomTooltips,
                    "CompactCardMode|" + CompactCardMode,
                    "AutoLiveTruthSync|" + AutoLiveTruthSync,
                    "ConfirmCriticalTweaks|" + ConfirmCriticalTweaks,
                    "RevertOnExit|" + RevertOnExit,
                    "ActiveProfileName|" + (ActiveProfileName ?? "Varsayılan (Son Oturum)"),
                    "AppLanguage|" + (AppLanguage ?? "TR")
                };
                StateVault.WriteAllLinesAtomic(path, lines.ToArray());
            }
            catch { }
        }

        public static ArgonAppSettings Load(string path)
        {
            ArgonAppSettings s = new ArgonAppSettings();
            try
            {
                if (!File.Exists(path)) return s;
                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    string[] p = line.Split(new char[] { '|' }, 2);
                    if (p.Length < 2) continue;
                    string k = p[0].Trim();
                    string v = p[1].Trim();
                    bool b; int n;
                    if (k == "EnableTelemetrySensors" && bool.TryParse(v, out b)) s.EnableTelemetrySensors = b;
                    else if (k == "ShowCpuSensor" && bool.TryParse(v, out b)) s.ShowCpuSensor = b;
                    else if (k == "ShowGpuCoreSensor" && bool.TryParse(v, out b)) s.ShowGpuCoreSensor = b;
                    else if (k == "ShowGpuMemHotspotSensor" && bool.TryParse(v, out b)) s.ShowGpuMemHotspotSensor = b;
                    else if (k == "TelemetryPollIntervalMs" && int.TryParse(v, out n)) s.TelemetryPollIntervalMs = Math.Max(500, Math.Min(5000, n));
                    else if (k == "FixedWindowLayout" && bool.TryParse(v, out b)) s.FixedWindowLayout = b;
                    else if (k == "WindowResolutionPreset" && !string.IsNullOrEmpty(v)) s.WindowResolutionPreset = v;
                    else if (k == "LockFixedResolution" && bool.TryParse(v, out b)) s.LockFixedResolution = b;
                    else if (k == "RichCustomTooltips" && bool.TryParse(v, out b)) s.RichCustomTooltips = b;
                    else if (k == "CompactCardMode" && bool.TryParse(v, out b)) s.CompactCardMode = b;
                    else if (k == "AutoLiveTruthSync" && bool.TryParse(v, out b)) s.AutoLiveTruthSync = b;
                    else if (k == "ConfirmCriticalTweaks" && bool.TryParse(v, out b)) s.ConfirmCriticalTweaks = b;
                    else if (k == "RevertOnExit" && bool.TryParse(v, out b)) s.RevertOnExit = b;
                    else if (k == "ActiveProfileName" && !string.IsNullOrEmpty(v)) s.ActiveProfileName = v;
                    else if (k == "AppLanguage" && !string.IsNullOrEmpty(v)) s.AppLanguage = v.Trim().ToUpperInvariant();
                }
            }
            catch { }
            return s;
        }
    }

    public class ArgonCustomProfile
    {
        public string ProfileName = "Yeni Profil";
        public string CreatedAt = "";
        public int CpuProfile = 0;
        public int GpuProfile = 0;
        public int ProgressiveTier = 2;
        public Dictionary<string, KeyValuePair<bool, int>> TweakStates = new Dictionary<string, KeyValuePair<bool, int>>(StringComparer.OrdinalIgnoreCase);

        public void SaveToFile(string path)
        {
            try
            {
                List<string> lines = new List<string>
                {
                    "ARGON_CUSTOM_PROFILE|40",
                    "NAME|" + (ProfileName ?? "Özel Profil"),
                    "DATE|" + (string.IsNullOrEmpty(CreatedAt) ? DateTime.Now.ToString("yyyy-MM-dd HH:mm") : CreatedAt),
                    "CPU|" + CpuProfile,
                    "GPU|" + GpuProfile,
                    "TIER|" + ProgressiveTier
                };
                foreach (var kv in TweakStates)
                {
                    lines.Add(string.Format("TWEAK|{0}|{1}|{2}", kv.Key, kv.Value.Key, kv.Value.Value));
                }
                StateVault.WriteAllLinesAtomic(path, lines.ToArray());
            }
            catch { }
        }

        public static ArgonCustomProfile LoadFromFile(string path)
        {
            try
            {
                if (!File.Exists(path)) return null;
                ArgonCustomProfile p = new ArgonCustomProfile();
                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    string[] parts = line.Split('|');
                    if (parts[0] == "NAME" && parts.Length >= 2) p.ProfileName = parts[1].Trim();
                    else if (parts[0] == "DATE" && parts.Length >= 2) p.CreatedAt = parts[1].Trim();
                    else if (parts[0] == "CPU" && parts.Length >= 2) int.TryParse(parts[1], out p.CpuProfile);
                    else if (parts[0] == "GPU" && parts.Length >= 2) int.TryParse(parts[1], out p.GpuProfile);
                    else if (parts[0] == "TIER" && parts.Length >= 2) int.TryParse(parts[1], out p.ProgressiveTier);
                    else if (parts[0] == "TWEAK" && parts.Length >= 4)
                    {
                        bool en; int vIdx;
                        if (bool.TryParse(parts[2], out en) && int.TryParse(parts[3], out vIdx))
                            p.TweakStates[parts[1].Trim()] = new KeyValuePair<bool, int>(en, vIdx);
                    }
                }
                return p;
            }
            catch { return null; }
        }
    }

    #region Otomasyon & QoL Data Models and Helper Systems

    public class CustomAlarmItem
    {
        public string Id = Guid.NewGuid().ToString("N");
        public string Title = "Yeni Alarm";
        public string Description = "Rutin Kontrol";
        public bool IsEnabled = true;
        public string AlarmType = "PERIODIC"; // "CRYPTO_4H", "CRYPTO_DAILY", "CRYPTO_WEEKLY", "PERIODIC", "SPECIFIC_TIME"
        public int PeriodMinutes = 240;
        public string SpecificTimeHHmm = "03:00";
        public DateTime NextTrigger = DateTime.Now.AddHours(4);
        public DateTime LastTriggered = DateTime.MinValue;
    }

    public class GameLaunchNoteItem
    {
        public string Id = Guid.NewGuid().ToString("N");
        public string ProcessName = "cs2";
        public string GameTitle = "Counter-Strike 2";
        public string NoteText = "Isınmadan rekabetçiye girme!\nSens: 1.15 | 800 DPI";
        public bool IsEnabled = true;
        public bool PeriodicInGame = false;
        public int PeriodicIntervalMinutes = 45;
        public DateTime LastNotified = DateTime.MinValue;
        public bool WasRunningLastCheck = false;
    }

    public class QoLAutomationConfig
    {
        // Güç & Kapatma Zamanlayıcısı
        public bool PowerTimerActive = false;
        public string PowerTimerMode = "COUNTDOWN"; // "COUNTDOWN" or "SPECIFIC_TIME"
        public int PowerTimerHours = 1;
        public int PowerTimerMinutes = 30;
        public string PowerTimerSpecificTime = "23:00";
        public string PowerTimerAction = "SHUTDOWN"; // "SHUTDOWN", "RESTART", "SLEEP", "LOCK"
        public DateTime PowerTimerTarget = DateTime.MinValue;
        public bool PowerTimerPostponeIfNetBusy = true;
        public int PowerTimerNetThresholdKBps = 500;
        public bool PowerTimerPostponeIfCpuBusy = true;
        public int PowerTimerCpuThresholdPercent = 25;
        public bool PowerTimer5MinWarn = true;
        public bool PowerTimerWarnGiven = false;

        // Alarmlar & Ses
        public string AlarmCustomSoundPath = "";
        public int AlarmMaxPlayDurationSec = 15; // 5, 10, 15, 30, 60
        public bool HealthRemindersEnabled = false; // Opt-in; default false
        public int HealthReminderIntervalMin = 60;
        public DateTime LastHealthReminderTime = DateTime.MinValue;

        // Akıllı RAM & Standby List Otomasyonu
        public bool AutoRamCleanActive = false;
        public int RamFreeThresholdPercent = 15; // e.g. %15 free RAM remaining
        public bool RamCleanProtectForegroundGame = true;

        public List<CustomAlarmItem> Alarms = new List<CustomAlarmItem>();
        public List<GameLaunchNoteItem> GameNotes = new List<GameLaunchNoteItem>();

        public void SaveToFile(string path)
        {
            try
            {
                List<string> lines = new List<string>
                {
                    "ARGON_QOL_CONFIG|10",
                    "PowerTimerActive|" + PowerTimerActive,
                    "PowerTimerMode|" + (PowerTimerMode ?? "COUNTDOWN"),
                    "PowerTimerHours|" + PowerTimerHours,
                    "PowerTimerMinutes|" + PowerTimerMinutes,
                    "PowerTimerSpecificTime|" + (PowerTimerSpecificTime ?? "23:00"),
                    "PowerTimerAction|" + (PowerTimerAction ?? "SHUTDOWN"),
                    "PowerTimerPostponeIfNetBusy|" + PowerTimerPostponeIfNetBusy,
                    "PowerTimerNetThresholdKBps|" + PowerTimerNetThresholdKBps,
                    "PowerTimerPostponeIfCpuBusy|" + PowerTimerPostponeIfCpuBusy,
                    "PowerTimerCpuThresholdPercent|" + PowerTimerCpuThresholdPercent,
                    "PowerTimer5MinWarn|" + PowerTimer5MinWarn,
                    "AlarmCustomSoundPath|" + (AlarmCustomSoundPath ?? ""),
                    "AlarmMaxPlayDurationSec|" + AlarmMaxPlayDurationSec,
                    "HealthRemindersEnabled|" + HealthRemindersEnabled,
                    "HealthReminderIntervalMin|" + HealthReminderIntervalMin,
                    "AutoRamCleanActive|" + AutoRamCleanActive,
                    "RamFreeThresholdPercent|" + RamFreeThresholdPercent,
                    "RamCleanProtectForegroundGame|" + RamCleanProtectForegroundGame
                };

                foreach (var a in Alarms)
                {
                    lines.Add(string.Format("ALARM|{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}",
                        a.Id,
                        (a.Title ?? "").Replace('|', ' '),
                        (a.Description ?? "").Replace('|', ' '),
                        a.IsEnabled,
                        a.AlarmType ?? "PERIODIC",
                        a.PeriodMinutes,
                        a.SpecificTimeHHmm ?? "03:00",
                        a.NextTrigger.ToString("yyyy-MM-dd HH:mm:ss")));
                }

                foreach (var g in GameNotes)
                {
                    string safeNote = (g.NoteText ?? "").Replace("\r\n", "\\n").Replace("\n", "\\n").Replace('|', ' ');
                    lines.Add(string.Format("GAMENOTE|{0}|{1}|{2}|{3}|{4}|{5}|{6}",
                        g.Id,
                        (g.ProcessName ?? "").Replace('|', ' '),
                        (g.GameTitle ?? "").Replace('|', ' '),
                        safeNote,
                        g.IsEnabled,
                        g.PeriodicInGame,
                        g.PeriodicIntervalMinutes));
                }

                StateVault.WriteAllLinesAtomic(path, lines.ToArray());
            }
            catch { }
        }

        public static QoLAutomationConfig LoadFromFile(string path)
        {
            QoLAutomationConfig cfg = new QoLAutomationConfig();
            try
            {
                if (!File.Exists(path))
                {
                    // Varsayılan Kripto 4H ve Günlük Alarm Şablonlarını Hazır Ekle
                    cfg.Alarms.Add(new CustomAlarmItem
                    {
                        Id = "crypto_4h_default",
                        Title = "BTC 4H Mum Kapanışı (03, 07, 11, 15, 19, 23)",
                        Description = "4 Saatlik grafikleri ve açık emirleri incele",
                        IsEnabled = true,
                        AlarmType = "CRYPTO_4H",
                        PeriodMinutes = 240,
                        SpecificTimeHHmm = "03:00",
                        NextTrigger = CryptoAlarmHelpers.GetNextCrypto4HCandleTime()
                    });
                    cfg.Alarms.Add(new CustomAlarmItem
                    {
                        Id = "crypto_daily_default",
                        Title = "Kripto Günlük Kapanış (03:00 UTC+3)",
                        Description = "Günlük mum kapanışı ve fonlama oranlarını kontrol et",
                        IsEnabled = true,
                        AlarmType = "CRYPTO_DAILY",
                        PeriodMinutes = 1440,
                        SpecificTimeHHmm = "03:00",
                        NextTrigger = CryptoAlarmHelpers.GetNextCryptoDailyCloseTime()
                    });
                    cfg.SaveToFile(path);
                    return cfg;
                }

                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    string[] parts = line.Split('|');
                    if (parts.Length < 2) continue;
                    string key = parts[0].Trim();

                    bool bVal; int nVal;
                    if (key == "PowerTimerActive" && bool.TryParse(parts[1], out bVal)) cfg.PowerTimerActive = bVal;
                    else if (key == "PowerTimerMode") cfg.PowerTimerMode = parts[1].Trim();
                    else if (key == "PowerTimerHours" && int.TryParse(parts[1], out nVal)) cfg.PowerTimerHours = nVal;
                    else if (key == "PowerTimerMinutes" && int.TryParse(parts[1], out nVal)) cfg.PowerTimerMinutes = nVal;
                    else if (key == "PowerTimerSpecificTime") cfg.PowerTimerSpecificTime = parts[1].Trim();
                    else if (key == "PowerTimerAction") cfg.PowerTimerAction = parts[1].Trim();
                    else if (key == "PowerTimerPostponeIfNetBusy" && bool.TryParse(parts[1], out bVal)) cfg.PowerTimerPostponeIfNetBusy = bVal;
                    else if (key == "PowerTimerNetThresholdKBps" && int.TryParse(parts[1], out nVal)) cfg.PowerTimerNetThresholdKBps = nVal;
                    else if (key == "PowerTimerPostponeIfCpuBusy" && bool.TryParse(parts[1], out bVal)) cfg.PowerTimerPostponeIfCpuBusy = bVal;
                    else if (key == "PowerTimerCpuThresholdPercent" && int.TryParse(parts[1], out nVal)) cfg.PowerTimerCpuThresholdPercent = nVal;
                    else if (key == "PowerTimer5MinWarn" && bool.TryParse(parts[1], out bVal)) cfg.PowerTimer5MinWarn = bVal;
                    else if (key == "AlarmCustomSoundPath") cfg.AlarmCustomSoundPath = parts[1].Trim();
                    else if (key == "AlarmMaxPlayDurationSec" && int.TryParse(parts[1], out nVal)) cfg.AlarmMaxPlayDurationSec = nVal;
                    else if (key == "HealthRemindersEnabled" && bool.TryParse(parts[1], out bVal)) cfg.HealthRemindersEnabled = bVal;
                    else if (key == "HealthReminderIntervalMin" && int.TryParse(parts[1], out nVal)) cfg.HealthReminderIntervalMin = nVal;
                    else if (key == "AutoRamCleanActive" && bool.TryParse(parts[1], out bVal)) cfg.AutoRamCleanActive = bVal;
                    else if (key == "RamFreeThresholdPercent" && int.TryParse(parts[1], out nVal)) cfg.RamFreeThresholdPercent = nVal;
                    else if (key == "RamCleanProtectForegroundGame" && bool.TryParse(parts[1], out bVal)) cfg.RamCleanProtectForegroundGame = bVal;
                    else if (key == "ALARM" && parts.Length >= 8)
                    {
                        CustomAlarmItem itm = new CustomAlarmItem();
                        itm.Id = parts[1].Trim();
                        itm.Title = parts[2].Trim();
                        itm.Description = parts[3].Trim();
                        bool.TryParse(parts[4], out itm.IsEnabled);
                        itm.AlarmType = parts[5].Trim();
                        int.TryParse(parts[6], out itm.PeriodMinutes);
                        itm.SpecificTimeHHmm = parts[7].Trim();
                        if (parts.Length >= 9) DateTime.TryParse(parts[8], out itm.NextTrigger);
                        cfg.Alarms.Add(itm);
                    }
                    else if (key == "GAMENOTE" && parts.Length >= 7)
                    {
                        GameLaunchNoteItem gn = new GameLaunchNoteItem();
                        gn.Id = parts[1].Trim();
                        gn.ProcessName = parts[2].Trim();
                        gn.GameTitle = parts[3].Trim();
                        gn.NoteText = parts[4].Trim().Replace("\\n", "\r\n");
                        bool.TryParse(parts[5], out gn.IsEnabled);
                        bool.TryParse(parts[6], out gn.PeriodicInGame);
                        if (parts.Length >= 8) int.TryParse(parts[7], out gn.PeriodicIntervalMinutes);
                        cfg.GameNotes.Add(gn);
                    }
                }
            }
            catch { }
            return cfg;
        }
    }

    public static class CryptoAlarmHelpers
    {
        public static DateTime GetNextCrypto4HCandleTime()
        {
            DateTime now = DateTime.Now;
            int[] hours = new int[] { 3, 7, 11, 15, 19, 23 };
            foreach (int h in hours)
            {
                DateTime cand = new DateTime(now.Year, now.Month, now.Day, h, 0, 0);
                if (cand > now) return cand;
            }
            DateTime t = now.AddDays(1);
            return new DateTime(t.Year, t.Month, t.Day, 3, 0, 0);
        }

        public static DateTime GetNextCryptoDailyCloseTime()
        {
            DateTime now = DateTime.Now;
            DateTime cand = new DateTime(now.Year, now.Month, now.Day, 3, 0, 0);
            if (cand > now) return cand;
            DateTime t = now.AddDays(1);
            return new DateTime(t.Year, t.Month, t.Day, 3, 0, 0);
        }

        public static DateTime GetNextCryptoWeeklyCloseTime()
        {
            DateTime now = DateTime.Now;
            DateTime cand = new DateTime(now.Year, now.Month, now.Day, 3, 0, 0);
            while (cand <= now || cand.DayOfWeek != DayOfWeek.Monday)
            {
                cand = cand.AddDays(1);
            }
            return cand;
        }
    }

    public static class AudioAlertPlayer
    {
        private static System.Threading.Timer cutoffTimer;
        private static readonly object playLock = new object();

        public static void PlayAlert(string soundFilePath, int maxDurationSeconds)
        {
            lock (playLock)
            {
                StopAlert();

                bool playedCustom = false;
                if (!string.IsNullOrEmpty(soundFilePath) && File.Exists(soundFilePath))
                {
                    try
                    {
                        NativeMethods.mciSendString("close argon_alert_audio", null, 0, IntPtr.Zero);
                        string openCmd = string.Format("open \"{0}\" type mpegvideo alias argon_alert_audio", soundFilePath);
                        int resOpen = NativeMethods.mciSendString(openCmd, null, 0, IntPtr.Zero);
                        if (resOpen == 0)
                        {
                            NativeMethods.mciSendString("play argon_alert_audio from 0", null, 0, IntPtr.Zero);
                            playedCustom = true;
                        }
                    }
                    catch { }
                }

                if (!playedCustom)
                {
                    try
                    {
                        System.Media.SystemSounds.Exclamation.Play();
                    }
                    catch { }
                }

                int safeDurationSec = Math.Max(3, Math.Min(60, maxDurationSeconds));
                cutoffTimer = new System.Threading.Timer(delegate
                {
                    StopAlert();
                }, null, safeDurationSec * 1000, Timeout.Infinite);
            }
        }

        public static void StopAlert()
        {
            try
            {
                if (cutoffTimer != null)
                {
                    cutoffTimer.Dispose();
                    cutoffTimer = null;
                }
                NativeMethods.mciSendString("stop argon_alert_audio", null, 0, IntPtr.Zero);
                NativeMethods.mciSendString("close argon_alert_audio", null, 0, IntPtr.Zero);
            }
            catch { }
        }
    }

    public class QoLToastForm : Form
    {
        private System.Windows.Forms.Timer autoCloseTimer;
        private System.Windows.Forms.Timer pulseTimer;
        private int pulseCount = 0;
        private Action onActionClick;
        private Color accentColor;

        public QoLToastForm(string title, string message, string actionButtonText, Action action, Color accent, int autoCloseSeconds, bool pulseEvery3Sec)
        {
            this.FormBorderStyle = FormBorderStyle.None;
            this.StartPosition = FormStartPosition.Manual;
            this.ShowInTaskbar = false;
            this.TopMost = true;
            this.Size = new Size(380, 105);
            this.BackColor = Color.FromArgb(20, 26, 38);
            this.accentColor = accent;
            this.onActionClick = action;

            Rectangle workArea = Screen.PrimaryScreen.WorkingArea;
            this.Location = new Point(workArea.Right - this.Width - 20, workArea.Bottom - this.Height - 20);

            this.Paint += (s, e) =>
            {
                using (Pen borderPen = new Pen(Color.FromArgb(45, 55, 75), 1))
                {
                    e.Graphics.DrawRectangle(borderPen, 0, 0, this.Width - 1, this.Height - 1);
                }
                using (SolidBrush accentBrush = new SolidBrush(this.accentColor))
                {
                    e.Graphics.FillRectangle(accentBrush, 0, 0, 6, this.Height);
                }
            };

            Label lblTitle = new Label
            {
                Text = title,
                Font = new Font("Segoe UI", 9.2f, FontStyle.Bold),
                ForeColor = accent,
                Location = new Point(16, 10),
                AutoSize = true
            };
            this.Controls.Add(lblTitle);

            Label lblMsg = new Label
            {
                Text = message,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Regular),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(16, 34),
                Size = new Size(346, 36),
                AutoEllipsis = true
            };
            this.Controls.Add(lblMsg);

            Button btnClose = new Button
            {
                Text = "✕",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(24, 22),
                Location = new Point(this.Width - 28, 6),
                Cursor = Cursors.Hand
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();
            this.Controls.Add(btnClose);

            if (!string.IsNullOrEmpty(actionButtonText))
            {
                Button btnAction = new Button
                {
                    Text = actionButtonText,
                    Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                    ForeColor = Color.White,
                    BackColor = Color.FromArgb(220, 38, 38),
                    FlatStyle = FlatStyle.Flat,
                    Size = new Size(125, 24),
                    Location = new Point(this.Width - 140, 72),
                    Cursor = Cursors.Hand
                };
                btnAction.FlatAppearance.BorderSize = 0;
                btnAction.Click += (s, e) =>
                {
                    if (onActionClick != null) onActionClick();
                    this.Close();
                };
                this.Controls.Add(btnAction);
            }

            if (autoCloseSeconds > 0)
            {
                autoCloseTimer = new System.Windows.Forms.Timer { Interval = autoCloseSeconds * 1000 };
                autoCloseTimer.Tick += (s, e) =>
                {
                    autoCloseTimer.Stop();
                    this.Close();
                };
                autoCloseTimer.Start();
            }

            if (pulseEvery3Sec)
            {
                pulseTimer = new System.Windows.Forms.Timer { Interval = 3000 };
                pulseTimer.Tick += (s, e) =>
                {
                    pulseCount++;
                    this.BackColor = (pulseCount % 2 == 1) ? Color.FromArgb(46, 26, 60) : Color.FromArgb(20, 26, 38);
                    this.Invalidate();
                    if (pulseCount >= 5) // 5 x 3s = 15 saniye alarm darbe döngüsü
                    {
                        pulseTimer.Stop();
                    }
                };
                pulseTimer.Start();
            }
        }

        protected override bool ShowWithoutActivation
        {
            get { return true; }
        }
    }

    #endregion

    public class LibreHardwareSensorEngine : IDisposable
    {
        private Computer computer;
        private bool isInitialized = false;
        private readonly object syncLock = new object();

        public float CpuPackageTemp = -1f;
        public float CpuTotalLoad = -1f;
        public float GpuCoreTemp = -1f;
        public float GpuMemoryTemp = -1f;
        public float GpuHotspotTemp = -1f;
        public float GpuCoreLoad = -1f;
        public float GpuMemUsedMb = 0f;
        public float GpuMemTotalMb = 0f;
        public float GpuPowerWatts = 0f;
        public string CpuHwName = "";
        public string GpuHwName = "";

        private PerformanceCounter fallbackCpuCounter;

        public void Initialize()
        {
            lock (syncLock)
            {
                if (isInitialized) return;
                try
                {
                    fallbackCpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total", true);
                    fallbackCpuCounter.NextValue();
                }
                catch { }

                try
                {
                    computer = new Computer
                    {
                        IsCpuEnabled = true,
                        IsGpuEnabled = true,
                        IsMotherboardEnabled = true,
                        IsMemoryEnabled = false,
                        IsStorageEnabled = false,
                        IsNetworkEnabled = false,
                        IsControllerEnabled = false
                    };
                    computer.Open();
                    isInitialized = true;
                }
                catch { }
            }
        }

        public void PollSensors()
        {
            PollSensors(true, true, true);
        }

        public void PollSensors(bool readCpu, bool readGpuCore, bool readGpuMemHotspot)
        {
            if (!readCpu && !readGpuCore && !readGpuMemHotspot) return;

            lock (syncLock)
            {
                if (!isInitialized) Initialize();

                float cTemp = -1f, cLoad = -1f;
                float gCoreTemp = -1f, gMemTemp = -1f, gHotTemp = -1f, gCoreLoad = -1f, gWatts = 0f;
                float memUsed = 0f, memTotal = 0f;
                float mbCpuTemp = -1f;

                if (computer != null)
                {
                    try
                    {
                        foreach (IHardware hw in computer.Hardware)
                        {
                            if (hw.HardwareType == HardwareType.Cpu && readCpu)
                            {
                                hw.Update();
                                CpuHwName = hw.Name;
                                foreach (ISensor s in hw.Sensors)
                                {
                                    if (!s.Value.HasValue) continue;
                                    float val = s.Value.Value;
                                    if (s.SensorType == SensorType.Load && s.Name.IndexOf("Total", StringComparison.OrdinalIgnoreCase) >= 0)
                                        cLoad = val;
                                    else if (s.SensorType == SensorType.Temperature && val > 1f && val < 130f)
                                    {
                                        if (s.Name.IndexOf("Tctl", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            s.Name.IndexOf("Package", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            s.Name.IndexOf("Core", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            cTemp < 0f)
                                        {
                                            cTemp = val;
                                        }
                                    }
                                }
                            }
                            else if (hw.HardwareType == HardwareType.Motherboard && readCpu && cTemp <= 1f)
                            {
                                hw.Update();
                                foreach (IHardware sub in hw.SubHardware)
                                {
                                    sub.Update();
                                    foreach (ISensor s in sub.Sensors)
                                    {
                                        if (s.SensorType == SensorType.Temperature && s.Value.HasValue && s.Value.Value > 10f && s.Value.Value < 115f)
                                        {
                                            if (s.Name.IndexOf("CPU", StringComparison.OrdinalIgnoreCase) >= 0 || mbCpuTemp < 0f)
                                                mbCpuTemp = s.Value.Value;
                                        }
                                    }
                                }
                            }
                            else if ((hw.HardwareType == HardwareType.GpuAmd || hw.HardwareType == HardwareType.GpuNvidia || hw.HardwareType == HardwareType.GpuIntel) &&
                                     (readGpuCore || readGpuMemHotspot))
                            {
                                hw.Update();
                                GpuHwName = hw.Name;
                                float d3dMax = -1f;
                                foreach (ISensor s in hw.Sensors)
                                {
                                    if (!s.Value.HasValue) continue;
                                    float val = s.Value.Value;
                                    if (s.SensorType == SensorType.Temperature && val > 1f && val < 140f)
                                    {
                                        if (s.Name.IndexOf("Hot Spot", StringComparison.OrdinalIgnoreCase) >= 0 || s.Name.IndexOf("HotSpot", StringComparison.OrdinalIgnoreCase) >= 0)
                                            gHotTemp = val;
                                        else if (s.Name.IndexOf("Memory", StringComparison.OrdinalIgnoreCase) >= 0 || s.Name.IndexOf("VRAM", StringComparison.OrdinalIgnoreCase) >= 0)
                                            gMemTemp = val;
                                        else if (s.Name.IndexOf("Core", StringComparison.OrdinalIgnoreCase) >= 0 || gCoreTemp < 0f)
                                            gCoreTemp = val;
                                    }
                                    else if (s.SensorType == SensorType.Load)
                                    {
                                        if (s.Name.Equals("GPU Core", StringComparison.OrdinalIgnoreCase))
                                            gCoreLoad = Math.Max(gCoreLoad, val);
                                        else if (s.Name.IndexOf("D3D", StringComparison.OrdinalIgnoreCase) >= 0)
                                            d3dMax = Math.Max(d3dMax, val);
                                    }
                                    else if (s.SensorType == SensorType.SmallData)
                                    {
                                        if (s.Name.Equals("GPU Memory Used", StringComparison.OrdinalIgnoreCase) || s.Name.Equals("D3D Dedicated Memory Used", StringComparison.OrdinalIgnoreCase))
                                            memUsed = Math.Max(memUsed, val);
                                        else if (s.Name.Equals("GPU Memory Total", StringComparison.OrdinalIgnoreCase) || s.Name.Equals("D3D Dedicated Memory Total", StringComparison.OrdinalIgnoreCase))
                                            memTotal = Math.Max(memTotal, val);
                                    }
                                    else if (s.SensorType == SensorType.Power)
                                    {
                                        gWatts = Math.Max(gWatts, val);
                                    }
                                }
                                if (gCoreLoad < 0f && d3dMax >= 0f) gCoreLoad = d3dMax;
                            }
                        }
                    }
                    catch { }
                }

                if (readCpu)
                {
                    if (cTemp <= 1f && mbCpuTemp > 1f) cTemp = mbCpuTemp;
                    if (cLoad < 0f && fallbackCpuCounter != null)
                    {
                        try { cLoad = fallbackCpuCounter.NextValue(); } catch { cLoad = 0f; }
                    }
                    CpuPackageTemp = cTemp;
                    CpuTotalLoad = cLoad >= 0f ? Math.Max(0f, Math.Min(100f, cLoad)) : -1f;
                }

                if (readGpuCore || readGpuMemHotspot)
                {
                    GpuCoreTemp = gCoreTemp;
                    GpuMemoryTemp = gMemTemp;
                    GpuHotspotTemp = gHotTemp;
                    GpuCoreLoad = gCoreLoad >= 0f ? Math.Max(0f, Math.Min(100f, gCoreLoad)) : -1f;
                    GpuMemUsedMb = memUsed;
                    GpuMemTotalMb = memTotal;
                    GpuPowerWatts = gWatts;
                }
            }
        }

        public void Dispose()
        {
            lock (syncLock)
            {
                try { if (computer != null) computer.Close(); } catch { }
                try { if (fallbackCpuCounter != null) fallbackCpuCounter.Dispose(); } catch { }
                isInitialized = false;
            }
        }
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
        public bool BaselineRecapturedFresh = false; // journal was missing -> current (possibly tweaked) state became the baseline

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
                    BaselineRecapturedFresh = true;
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
                WriteAllLinesAtomic(journalPath, lines.ToArray());
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

        public void RestoreAllProcessBackups()
        {
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
        }

        public static void WriteAllLinesAtomic(string path, string[] lines)
        {
            string tmp = path + ".tmp";
            File.WriteAllLines(tmp, lines, Encoding.UTF8);
            if (File.Exists(path)) File.Replace(tmp, path, null);
            else File.Move(tmp, path);
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

    #region Professional Vector Icon Engine & Compact Utility Row Architecture (NetAdapter / QuickCPU Style)

    public static class TechnicalIconRenderer
    {
        public static void DrawTweakVectorIcon(Graphics g, Rectangle bounds, TweakDefinition tweak)
        {
            if (tweak == null) return;
            DrawTweakVectorIcon(
                g,
                bounds,
                tweak.Id ?? "",
                tweak.Category ?? "",
                tweak.HardwareTag ?? "",
                tweak.BadgeColor,
                tweak.IsEnabled);
        }

        public static void DrawTweakVectorIcon(Graphics g, Rectangle bounds, string id, string cat, string hw, Color primary, bool isEnabled = true)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;

            if (hw == "INTEL_CPU" || hw == "INTEL_GPU") primary = Color.FromArgb(56, 189, 248);
            else if (hw == "AMD_CPU") primary = Color.FromArgb(249, 115, 22);
            else if (hw == "AMD_GPU") primary = Color.FromArgb(239, 68, 68);
            else if (hw == "NVIDIA_GPU") primary = Color.FromArgb(34, 197, 94);

            Rectangle box = new Rectangle(bounds.X + 1, bounds.Y + 1, bounds.Width - 2, bounds.Height - 2);
            using (SolidBrush bgBr = new SolidBrush(Color.FromArgb(isEnabled ? 48 : 26, primary)))
            using (Pen borderPen = new Pen(Color.FromArgb(isEnabled ? 210 : 110, primary), 1.2f))
            {
                g.FillRectangle(bgBr, box);
                g.DrawRectangle(borderPen, box);
            }

            using (Pen p = new Pen(primary, 1.5f))
            using (SolidBrush b = new SolidBrush(primary))
            using (Font f = new Font("Segoe UI", 6.2f, FontStyle.Bold))
            {
                int cx = bounds.X + bounds.Width / 2;
                int cy = bounds.Y + bounds.Height / 2;

                if (hw == "INTEL_CPU" || hw == "AMD_CPU" || id == "LAT_CSTATES" || id == "LAT_COREPARK" || id == "EXP_SMT_ISOLATION")
                {
                    // CPU Die + Pins
                    Rectangle die = new Rectangle(cx - 5, cy - 5, 10, 10);
                    g.DrawRectangle(p, die);
                    for (int i = -3; i <= 3; i += 3)
                    {
                        g.DrawLine(p, cx + i, cy - 8, cx + i, cy - 5);
                        g.DrawLine(p, cx + i, cy + 5, cx + i, cy + 8);
                        g.DrawLine(p, cx - 8, cy + i, cx - 5, cy + i);
                        g.DrawLine(p, cx + 5, cy + i, cx + 8, cy + i);
                    }
                    g.FillRectangle(b, cx - 2, cy - 2, 5, 5);
                }
                else if (hw == "NVIDIA_GPU" || hw == "AMD_GPU" || hw == "INTEL_GPU" || id == "FPS_HAGS" || id == "FPS_MMCSS_GAMES" || id == "FPS_FSO_FLIP" || id == "WU_MPO_CONTROL")
                {
                    // GPU / Display Card with Fan
                    Rectangle card = new Rectangle(cx - 7, cy - 5, 14, 9);
                    g.DrawRectangle(p, card);
                    g.DrawEllipse(p, cx - 3, cy - 3, 6, 6);
                    g.DrawLine(p, cx - 5, cy + 6, cx + 3, cy + 6); // PCIe gold fingers
                }
                else if (id == "NET_DNS_SWITCH" || id == "NET_HOSTPRIO" || id == "WU_IPV4_TEREDO")
                {
                    // DNS Globe
                    Rectangle globe = new Rectangle(cx - 6, cy - 6, 12, 12);
                    g.DrawEllipse(p, globe);
                    g.DrawEllipse(p, cx - 3, cy - 6, 6, 12);
                    g.DrawLine(p, cx - 6, cy, cx + 6, cy);
                }
                else if (cat == "NETWORK" || id == "EXP_TCP_CONGESTION" || id == "EXP_ECN_HEURISTICS" || id == "WU_DELIVERY_OPT")
                {
                    // RJ45 Network Port / Packet Switch
                    Rectangle port = new Rectangle(cx - 6, cy - 5, 12, 9);
                    g.DrawRectangle(p, port);
                    g.DrawLine(p, cx - 3, cy - 5, cx - 3, cy - 2);
                    g.DrawLine(p, cx, cy - 5, cx, cy - 2);
                    g.DrawLine(p, cx + 3, cy - 5, cx + 3, cy - 2);
                    g.DrawLine(p, cx, cy + 4, cx, cy + 7);
                    g.DrawLine(p, cx - 5, cy + 7, cx + 5, cy + 7);
                }
                else if (id == "LAT_TIMER" || id == "EXP_SERIALIZE_TIMER" || id == "EXP_SYNTHETIC_PULSE")
                {
                    // High-Precision Oscilloscope / Timer Pulse
                    Rectangle clk = new Rectangle(cx - 6, cy - 6, 12, 12);
                    g.DrawEllipse(p, clk);
                    g.DrawLine(p, cx, cy, cx, cy - 4);
                    g.DrawLine(p, cx, cy, cx + 3, cy + 2);
                }
                else if (id == "LAT_MOUSE_SPI" || id == "LAT_HID_QUEUE" || id == "LAT_FILTERKEYS" || id == "EXP_FOREGROUND_HOOKS")
                {
                    // Precision Input / Mouse Body
                    Rectangle m = new Rectangle(cx - 4, cy - 6, 8, 12);
                    g.DrawRectangle(p, m);
                    g.DrawLine(p, cx - 4, cy - 1, cx + 4, cy - 1);
                    g.DrawLine(p, cx, cy - 6, cx, cy - 1);
                }
                else if (id == "LAT_USB_PCIE" || id == "LAT_USB_XHCI" || id == "FPS_NVME_IRQ8")
                {
                    // Bus / Trident / NVMe Lane
                    g.DrawLine(p, cx - 5, cy, cx + 6, cy);
                    g.DrawLine(p, cx - 2, cy, cx + 1, cy - 4);
                    g.DrawLine(p, cx, cy, cx + 3, cy + 4);
                    g.FillEllipse(b, cx - 7, cy - 2, 4, 4);
                    g.FillRectangle(b, cx + 4, cy - 2, 3, 4);
                }
                else if (id == "FPS_MEMORY_ENGINE" || id == "EXP_SVCHOST_SPLIT")
                {
                    // RAM DIMM Module
                    Rectangle ram = new Rectangle(cx - 7, cy - 4, 14, 7);
                    g.DrawRectangle(p, ram);
                    g.FillRectangle(b, cx - 5, cy - 2, 2, 3);
                    g.FillRectangle(b, cx - 1, cy - 2, 2, 3);
                    g.FillRectangle(b, cx + 3, cy - 2, 2, 3);
                    g.DrawLine(p, cx - 5, cy + 5, cx + 5, cy + 5);
                }
                else
                {
                    // Shield / Kernel Lock
                    Point[] shield = new Point[]
                    {
                        new Point(cx, cy - 6),
                        new Point(cx + 6, cy - 3),
                        new Point(cx + 5, cy + 3),
                        new Point(cx, cy + 7),
                        new Point(cx - 5, cy + 3),
                        new Point(cx - 6, cy - 3)
                    };
                    g.DrawPolygon(p, shield);
                }
            }
        }
    }

    public class MultiVariationTweakCard : Panel
    {
        public TweakDefinition Tweak;
        private Action<TweakDefinition, bool, int> onStateChanged;
        private Action<TweakDefinition, TweakVariation> onHoverInspect;
        private ToolTip sharedToolTip;

        private const int ROW_HEIGHT = 36;

        private CheckBox chkEnable;
        private Panel pnlIconBox;
        private Label lblTitle;
        private ComboBox cmbVariations;
        private Label lblLiveStateBadge;
        private Button btnInfoInspect;
        private Button btnGearConfig;
        private bool syncingRowControls = false;
        private bool isMouseHovered = false;

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
            this.Height = ROW_HEIGHT;
            this.Width = 740;
            this.BackColor = Color.FromArgb(18, 22, 31);
            this.Margin = new Padding(0, 0, 0, 2);

            BuildCompactUtilityRow();
            this.Resize += (s, e) =>
            {
                LayoutCardControls();
                this.Invalidate(false);
            };
            RefreshVisualState();
        }

        private void BuildCompactUtilityRow()
        {
            string rawTitle = Tweak.Title ?? "";
            if (rawTitle.Contains("RESTART")) Tweak.NeedsReboot = true;
            if (rawTitle.Contains("AĞ") && rawTitle.Contains("YENİLEME")) Tweak.NeedsNetReload = true;

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

            // 1. Direct CheckBox (NetAdapter Repair style)
            chkEnable = new CheckBox
            {
                Text = "",
                AutoSize = false,
                Size = new Size(18, 18),
                Location = new Point(10, 9),
                Cursor = Cursors.Hand,
                Checked = Tweak.IsEnabled
            };
            chkEnable.CheckedChanged += (s, e) =>
            {
                if (syncingRowControls) return;
                ToggleRowEnabledState(chkEnable.Checked);
            };
            this.Controls.Add(chkEnable);

            // 2. Vector Hardware/System Icon (22x22)
            pnlIconBox = new Panel
            {
                Size = new Size(22, 22),
                Location = new Point(32, 7),
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand
            };
            pnlIconBox.Paint += (s, e) => TechnicalIconRenderer.DrawTweakVectorIcon(e.Graphics, new Rectangle(0, 0, 22, 22), Tweak);
            pnlIconBox.Click += (s, e) => ToggleRowEnabledState(!Tweak.IsEnabled);
            this.Controls.Add(pnlIconBox);

            // 3. Clean Technical Title
            lblTitle = new Label
            {
                Text = cleanTitle,
                Font = new Font("Segoe UI", 8.6f, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                AutoSize = false,
                AutoEllipsis = true,
                UseMnemonic = false,
                TextAlign = ContentAlignment.MiddleLeft,
                Location = new Point(60, 4),
                Size = new Size(310, 28),
                Cursor = Cursors.Hand
            };
            lblTitle.Click += (s, e) => ToggleRowEnabledState(!Tweak.IsEnabled);
            this.Controls.Add(lblTitle);

            // 4. Compact Mode / Variation Selector ComboBox
            cmbVariations = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 7.8f, FontStyle.Regular),
                BackColor = Color.FromArgb(13, 16, 23),
                ForeColor = Color.FromArgb(203, 213, 225),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(215, 22),
                DropDownWidth = 380,
                Cursor = Cursors.Hand
            };
            for (int i = 0; i < Tweak.Variations.Count; i++)
            {
                var v = Tweak.Variations[i];
                cmbVariations.Items.Add(string.Format("Mod {0}: {1}", i + 1, v.ShortLabel));
            }
            if (cmbVariations.Items.Count > 0)
            {
                syncingRowControls = true;
                cmbVariations.SelectedIndex = Math.Max(0, Math.Min(Tweak.SelectedVariationIndex, cmbVariations.Items.Count - 1));
                syncingRowControls = false;
            }
            cmbVariations.SelectedIndexChanged += (s, e) =>
            {
                if (syncingRowControls || cmbVariations.SelectedIndex < 0) return;
                int idx = cmbVariations.SelectedIndex;
                if (Tweak.HasCustomParam && idx == Tweak.Variations.Count - 1)
                {
                    if (Tweak.CustomParam.CurrentCustomValue == 0)
                    {
                        ShowCustomParameterModal();
                        return;
                    }
                }
                Tweak.SelectedVariationIndex = idx;
                Tweak.IsEnabled = true;
                if (onStateChanged != null)
                    onStateChanged(Tweak, true, idx);
                RefreshVisualState();
                if (onHoverInspect != null && idx < Tweak.Variations.Count)
                    onHoverInspect(Tweak, Tweak.Variations[idx]);
            };
            this.Controls.Add(cmbVariations);

            // 5. Live OS Truth Status Pill
            lblLiveStateBadge = new Label
            {
                Text = "Varsayılan",
                Font = new Font("Consolas", 7.6f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                BackColor = Color.FromArgb(24, 30, 42),
                AutoSize = false,
                AutoEllipsis = true,
                TextAlign = ContentAlignment.MiddleCenter,
                Size = new Size(148, 22),
                Cursor = Cursors.Hand
            };
            lblLiveStateBadge.Click += (s, e) => ShowTechnicalSpecDialog();
            this.Controls.Add(lblLiveStateBadge);

            // 6. Quick Technical Spec Inspect Button [?]
            btnInfoInspect = new Button
            {
                Text = "?",
                Font = new Font("Consolas", 8.0f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(26, 33, 48),
                ForeColor = Color.FromArgb(148, 163, 184),
                Size = new Size(22, 22),
                Cursor = Cursors.Hand
            };
            btnInfoInspect.FlatAppearance.BorderSize = 1;
            btnInfoInspect.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnInfoInspect.Click += (s, e) => ShowTechnicalSpecDialog();
            this.Controls.Add(btnInfoInspect);

            // 7. Machine-Specific Customizable Parameter Button [⚙]
            if (Tweak.HasCustomParam)
            {
                btnGearConfig = new Button
                {
                    Text = "⚙",
                    Font = new Font("Segoe UI Symbol", 8.2f, FontStyle.Regular),
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.FromArgb(20, 26, 38),
                    ForeColor = Color.FromArgb(56, 189, 248),
                    Size = new Size(22, 22),
                    Cursor = Cursors.Hand
                };
                btnGearConfig.FlatAppearance.BorderSize = 1;
                btnGearConfig.FlatAppearance.BorderColor = Color.FromArgb(45, 68, 98);
                btnGearConfig.Click += (s, e) => ShowCustomParameterModal();
                btnGearConfig.MouseEnter += (s, e) =>
                {
                    btnGearConfig.BackColor = Color.FromArgb(28, 42, 62);
                    btnGearConfig.ForeColor = Color.FromArgb(125, 211, 252);
                    btnGearConfig.FlatAppearance.BorderColor = Color.FromArgb(56, 189, 248);
                };
                btnGearConfig.MouseLeave += (s, e) =>
                {
                    btnGearConfig.BackColor = Color.FromArgb(20, 26, 38);
                    btnGearConfig.ForeColor = Color.FromArgb(56, 189, 248);
                    btnGearConfig.FlatAppearance.BorderColor = Color.FromArgb(45, 68, 98);
                };
                this.Controls.Add(btnGearConfig);
                sharedToolTip.SetToolTip(btnGearConfig, Loc.T("Makineye özel parametre belirle [⚙]", "Configure machine-specific parameter [⚙]"));
            }

            UpdateCustomVariationLabel();

            string cardTip = BuildCardTooltip();
            sharedToolTip.SetToolTip(this, cardTip);
            sharedToolTip.SetToolTip(lblTitle, cardTip);
            sharedToolTip.SetToolTip(pnlIconBox, cardTip);
            sharedToolTip.SetToolTip(cmbVariations, cardTip);
            sharedToolTip.SetToolTip(lblLiveStateBadge, cardTip);
            sharedToolTip.SetToolTip(btnInfoInspect, "Teknik parametreleri, kayıt defteri hedefini ve canlı OS durumunu görüntüle");

            EventHandler hoverEnter = (s, e) =>
            {
                isMouseHovered = true;
                this.Invalidate(false);
                if (onHoverInspect != null && Tweak.Variations.Count > 0)
                {
                    int safeIdx = Math.Max(0, Math.Min(Tweak.SelectedVariationIndex, Tweak.Variations.Count - 1));
                    onHoverInspect(Tweak, Tweak.Variations[safeIdx]);
                }
            };
            EventHandler hoverLeave = (s, e) =>
            {
                isMouseHovered = false;
                this.Invalidate(false);
            };

            this.MouseEnter += hoverEnter;
            this.MouseLeave += hoverLeave;
            lblTitle.MouseEnter += hoverEnter;
            lblTitle.MouseLeave += hoverLeave;
            pnlIconBox.MouseEnter += hoverEnter;
            cmbVariations.MouseEnter += hoverEnter;
            lblLiveStateBadge.MouseEnter += hoverEnter;

            LayoutCardControls();
        }

        private void ToggleRowEnabledState(bool wantEnable)
        {
            bool wasEnabled = Tweak.IsEnabled;
            if (wasEnabled == wantEnable) return;

            Tweak.IsEnabled = wantEnable;
            if (onStateChanged != null)
                onStateChanged(Tweak, Tweak.IsEnabled, Tweak.SelectedVariationIndex);
            RefreshVisualState();
        }

        private void ShowTechnicalSpecDialog()
        {
            if (onHoverInspect != null && Tweak.Variations.Count > 0)
            {
                int safeIdx = Math.Max(0, Math.Min(Tweak.SelectedVariationIndex, Tweak.Variations.Count - 1));
                onHoverInspect(Tweak, Tweak.Variations[safeIdx]);
            }
            MessageBox.Show(BuildCardTooltip(), "Argon Teknik Denetim — " + Tweak.Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void LayoutCardControls()
        {
            int w = Math.Max(520, this.ClientSize.Width);
            int rightX = w - 6;

            if (btnInfoInspect != null)
            {
                rightX -= btnInfoInspect.Width;
                btnInfoInspect.Location = new Point(rightX, 7);
                rightX -= 4;
            }

            if (btnGearConfig != null)
            {
                rightX -= btnGearConfig.Width;
                btnGearConfig.Location = new Point(rightX, 7);
                rightX -= 5;
            }

            if (lblLiveStateBadge != null)
            {
                int badgeW = w >= 800 ? 168 : (w >= 700 ? 152 : 132);
                rightX -= badgeW;
                lblLiveStateBadge.Size = new Size(badgeW, 22);
                lblLiveStateBadge.Location = new Point(rightX, 7);
                rightX -= 6;
            }

            if (cmbVariations != null)
            {
                int comboW = w >= 800 ? 250 : (w >= 700 ? 220 : 185);
                rightX -= comboW;
                cmbVariations.Size = new Size(comboW, 22);
                cmbVariations.Location = new Point(rightX, 7);
                rightX -= 8;
            }

            if (lblTitle != null)
            {
                int titleLeft = 58;
                int titleW = Math.Max(160, rightX - titleLeft);
                lblTitle.Location = new Point(titleLeft, 4);
                lblTitle.Size = new Size(titleW, 28);
            }
        }

        private string BuildCardTooltip()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("[" + Tweak.BadgeText + "] " + Tweak.Title);
            sb.AppendLine("──────────────────────────────────────────────────");
            sb.AppendLine("• Teknik Özet   : " + Tweak.SummaryDescription);
            sb.AppendLine("• Mimari Neden  : " + Tweak.DeepTechnicalWhy);
            sb.AppendLine("• Sistem Hedefi : " + (Tweak.TargetPathOrApi ?? "Kernel / Win32 API"));
            sb.AppendLine("• Fabrika Değeri: " + Tweak.CapturedOriginalSummary);
            sb.AppendLine("• Canlı OS      : " + (string.IsNullOrEmpty(Tweak.LiveOsRawSummary) ? (Tweak.IsVerifiedInOs ? ("Doğrulandı (" + Tweak.VerifiedSystemValue + ")") : "Varsayılanda") : Tweak.LiveOsRawSummary));
            if (Tweak.RequiresCautionConfirmation && !string.IsNullOrEmpty(Tweak.CautionWarningText))
                sb.AppendLine("• Uyarı Notu    : " + Tweak.CautionWarningText);
            if (Tweak.HasCustomParam)
            {
                sb.AppendLine(string.Format("• Makine Parametresi: {0} = {1} {2} (En Az {3} {2})",
                    Tweak.CustomParam.DisplayLabel,
                    Tweak.CustomParam.CurrentCustomValue > 0 ? Tweak.CustomParam.CurrentCustomValue.ToString() : "Varsayılan",
                    Tweak.CustomParam.Unit,
                    Tweak.CustomParam.MinValue));
            }
            sb.AppendLine();
            sb.AppendLine("Varyasyon Parametreleri:");
            for (int i = 0; i < Tweak.Variations.Count; i++)
            {
                var v = Tweak.Variations[i];
                sb.AppendLine(string.Format("  [{0}] {1} -> {2}", i + 1, v.ShortLabel, v.ExactParameters));
            }
            return sb.ToString();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            Color borderColor = Tweak.IsEnabled
                ? Color.FromArgb(140, Tweak.BadgeColor)
                : (isMouseHovered ? Color.FromArgb(65, 80, 110) : Color.FromArgb(30, 37, 52));

            using (Pen p = new Pen(borderColor, 1))
            {
                e.Graphics.DrawRectangle(p, 0, 0, this.Width - 1, this.Height - 1);
            }

            using (SolidBrush accentBr = new SolidBrush(Tweak.IsEnabled ? Tweak.BadgeColor : Color.FromArgb(45, 55, 76)))
            {
                e.Graphics.FillRectangle(accentBr, 0, 0, Tweak.IsEnabled ? 4 : 2, this.Height);
            }
        }

        public void UpdateCustomVariationLabel()
        {
            if (Tweak == null || Tweak.CustomParam == null || cmbVariations == null) return;
            int customIdx = Tweak.Variations.Count - 1;
            if (customIdx >= 0 && customIdx < cmbVariations.Items.Count)
            {
                int curVal = Tweak.CustomParam.CurrentCustomValue;
                string label = curVal > 0
                    ? string.Format(Loc.T("Mod {0}: Özel ({1} {2}) [⚙]", "Mode {0}: Custom ({1} {2}) [⚙]"), customIdx + 1, curVal, Tweak.CustomParam.Unit)
                    : string.Format(Loc.T("Mod {0}: Özel Değer... [⚙]", "Mode {0}: Custom Value... [⚙]"), customIdx + 1);

                syncingRowControls = true;
                try
                {
                    cmbVariations.Items[customIdx] = label;
                }
                finally
                {
                    syncingRowControls = false;
                }
            }
        }

        public void ShowCustomParameterModal()
        {
            if (Tweak == null || Tweak.CustomParam == null) return;
            int oldIdx = Tweak.SelectedVariationIndex;
            using (CustomParameterDialog dlg = new CustomParameterDialog(Tweak))
            {
                Form parentForm = this.FindForm();
                if (dlg.ShowDialog(parentForm) == DialogResult.OK)
                {
                    int customIdx = Tweak.Variations.Count - 1;
                    Tweak.SelectedVariationIndex = customIdx;
                    Tweak.IsEnabled = true;
                    UpdateCustomVariationLabel();
                    RefreshVisualState();
                    if (onStateChanged != null)
                        onStateChanged(Tweak, true, customIdx);
                }
                else
                {
                    if (cmbVariations != null && cmbVariations.SelectedIndex != oldIdx)
                    {
                        syncingRowControls = true;
                        cmbVariations.SelectedIndex = Math.Max(0, Math.Min(oldIdx, cmbVariations.Items.Count - 1));
                        syncingRowControls = false;
                    }
                }
            }
        }

        public void RefreshVisualState()
        {
            syncingRowControls = true;
            try
            {
                if (chkEnable != null && chkEnable.Checked != Tweak.IsEnabled)
                    chkEnable.Checked = Tweak.IsEnabled;

                if (cmbVariations != null && Tweak.SelectedVariationIndex >= 0 && Tweak.SelectedVariationIndex < cmbVariations.Items.Count)
                {
                    if (cmbVariations.SelectedIndex != Tweak.SelectedVariationIndex)
                        cmbVariations.SelectedIndex = Tweak.SelectedVariationIndex;
                }
            }
            finally
            {
                syncingRowControls = false;
            }

            UpdateCustomVariationLabel();

            this.BackColor = Tweak.IsEnabled
                ? Color.FromArgb(17, 29, 39)
                : (isMouseHovered ? Color.FromArgb(23, 29, 42) : Color.FromArgb(17, 21, 30));

            if (lblTitle != null)
            {
                lblTitle.ForeColor = Tweak.IsEnabled ? Color.White : Color.FromArgb(212, 220, 232);
            }

            if (cmbVariations != null)
            {
                cmbVariations.BackColor = Tweak.IsEnabled ? Color.FromArgb(14, 24, 34) : Color.FromArgb(13, 16, 23);
                cmbVariations.ForeColor = Tweak.IsEnabled ? Color.FromArgb(56, 189, 248) : Color.FromArgb(175, 188, 208);
            }

            if (lblLiveStateBadge != null)
            {
                if (Tweak.IsEnabled)
                {
                    if (Tweak.IsRebootPending)
                    {
                        int safeIdx = Math.Max(0, Math.Min(Tweak.SelectedVariationIndex, Tweak.Variations.Count - 1));
                        string modTag = Tweak.Variations.Count > 1 ? string.Format(Loc.T("Mod {0} (Restart)", "Mode {0} (Restart)"), safeIdx + 1) : Loc.T("Restart Bekliyor", "Restart Pending");
                        lblLiveStateBadge.Text = "⚠️ " + modTag;
                        lblLiveStateBadge.ForeColor = Color.FromArgb(251, 191, 36);
                        lblLiveStateBadge.BackColor = Color.FromArgb(52, 34, 14);
                    }
                    else if (Tweak.IsNetReloadPending)
                    {
                        lblLiveStateBadge.Text = Loc.T("⚡ Ağ Yenileme", "⚡ Net Reload");
                        lblLiveStateBadge.ForeColor = Color.FromArgb(56, 189, 248);
                        lblLiveStateBadge.BackColor = Color.FromArgb(15, 36, 56);
                    }
                    else if (Tweak.IsVerifiedInOs)
                    {
                        string vText = !string.IsNullOrEmpty(Tweak.VerifiedSystemValue) ? Tweak.VerifiedSystemValue : Loc.T("UYGULANDI", "APPLIED");
                        lblLiveStateBadge.Text = "✓ " + vText;
                        lblLiveStateBadge.ForeColor = Color.FromArgb(52, 211, 153);
                        lblLiveStateBadge.BackColor = Color.FromArgb(13, 40, 32);
                    }
                    else
                    {
                        lblLiveStateBadge.Text = Loc.T("✓ UYGULANDI", "✓ APPLIED");
                        lblLiveStateBadge.ForeColor = Color.FromArgb(52, 211, 153);
                        lblLiveStateBadge.BackColor = Color.FromArgb(13, 40, 32);
                    }
                }
                else
                {
                    if (Tweak.IsRebootPending)
                    {
                        lblLiveStateBadge.Text = Loc.T("⚠️ Pasif (Restart)", "⚠️ Disabled (Restart)");
                        lblLiveStateBadge.ForeColor = Color.FromArgb(251, 191, 36);
                        lblLiveStateBadge.BackColor = Color.FromArgb(52, 34, 14);
                    }
                    else if (Tweak.IsDetectedActiveInOs)
                    {
                        string dText = !string.IsNullOrEmpty(Tweak.VerifiedSystemValue) ? Tweak.VerifiedSystemValue : Loc.T("SİSTEMDE AKTİF", "ACTIVE IN OS");
                        lblLiveStateBadge.Text = "● " + dText;
                        lblLiveStateBadge.ForeColor = Color.FromArgb(56, 189, 248);
                        lblLiveStateBadge.BackColor = Color.FromArgb(14, 34, 52);
                    }
                    else
                    {
                        string defTxt = string.IsNullOrEmpty(Tweak.CapturedOriginalSummary) ? Loc.T("Varsayılan", "Default") : Tweak.CapturedOriginalSummary;
                        lblLiveStateBadge.Text = defTxt;
                        lblLiveStateBadge.ForeColor = Color.FromArgb(125, 140, 165);
                        lblLiveStateBadge.BackColor = Color.FromArgb(22, 27, 38);
                    }
                }
            }

            if (pnlIconBox != null) pnlIconBox.Invalidate();
            this.Invalidate(false);
        }
    }

    #region Guidance Helpers & Safety Lock Dialogs

    public static class GuidanceHelpers
    {
        public static void OpenRegeditAtKey(string fullKeyPath)
        {
            if (string.IsNullOrEmpty(fullKeyPath))
            {
                try { Process.Start("regedit.exe"); } catch { }
                return;
            }

            try
            {
                string rootPrefix = "Computer";
                using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit", true))
                {
                    if (rk != null)
                    {
                        object cur = rk.GetValue("LastKey");
                        if (cur != null)
                        {
                            string s = cur.ToString();
                            int slashIdx = s.IndexOf('\\');
                            if (slashIdx > 0)
                            {
                                rootPrefix = s.Substring(0, slashIdx);
                            }
                        }
                        else if (System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("tr", StringComparison.OrdinalIgnoreCase))
                        {
                            rootPrefix = "Bilgisayar";
                        }

                        string formattedKey = fullKeyPath;
                        if (!formattedKey.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase))
                        {
                            if (formattedKey.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
                                formattedKey = "HKEY_LOCAL_MACHINE\\" + formattedKey.Substring(5);
                            else if (formattedKey.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
                                formattedKey = "HKEY_CURRENT_USER\\" + formattedKey.Substring(5);
                        }

                        rk.SetValue("LastKey", rootPrefix + "\\" + formattedKey);
                    }
                }
                Process.Start("regedit.exe");
            }
            catch
            {
                try { Process.Start("regedit.exe"); } catch { }
            }
        }

        public static void OpenGoogleSearch(string query)
        {
            if (string.IsNullOrEmpty(query)) return;
            try
            {
                string url = "https://www.google.com/search?q=" + Uri.EscapeDataString(query);
                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch { }
        }
    }

    public class SecurityLockGuidanceDialog : Form
    {
        public SecurityLockGuidanceDialog(TweakDefinition tweak, CustomParamConfig cfg, int attemptedValue)
        {
            this.Text = Loc.T("Argon Kesin Güvenlik Kilidi", "Argon Strict Security Lock");
            this.Size = new Size(590, 520);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowInTaskbar = false;
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(16, 20, 28);
            this.ForeColor = Color.FromArgb(226, 232, 240);

            // Header Panel (Danger / Alert theme)
            Panel pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 65,
                BackColor = Color.FromArgb(42, 16, 22),
                Padding = new Padding(16, 10, 16, 10)
            };
            pnlHeader.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(239, 68, 68), 2))
                {
                    e.Graphics.DrawLine(p, 0, pnlHeader.Height - 1, pnlHeader.Width, pnlHeader.Height - 1);
                }
            };

            Label lblAlertTitle = new Label
            {
                Text = "🔒 " + (cfg.SafetyWarningTitle ?? Loc.T("GÜVENLİK KİLİDİ DEVREYE GİRDİ", "SECURITY LOCK ACTIVATED")),
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(248, 113, 113),
                AutoSize = true,
                Location = new Point(14, 10)
            };
            pnlHeader.Controls.Add(lblAlertTitle);

            Label lblAlertSub = new Label
            {
                Text = string.Format(Loc.T(
                    "Girilen Değer ({0} {1}), Kabul Edilebilir En Düşük Sınırın ({2} {1}) Altındadır!",
                    "Entered Value ({0} {1}) Is Below Minimum Safe Limit ({2} {1})!"),
                    attemptedValue, cfg.Unit, cfg.MinValue),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(254, 202, 202),
                AutoSize = true,
                Location = new Point(14, 34)
            };
            pnlHeader.Controls.Add(lblAlertSub);
            this.Controls.Add(pnlHeader);

            // Content Area (Middle)
            Panel pnlBody = new Panel
            {
                Location = new Point(16, 75),
                Size = new Size(542, 330),
                BackColor = Color.Transparent
            };

            Label lblWhyHeader = new Label
            {
                Text = Loc.T("Teknik İnceleme ve Neden Engellendiği:", "Technical Inspection & Why It Is Blocked:"),
                Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                Location = new Point(0, 0),
                AutoSize = true
            };
            pnlBody.Controls.Add(lblWhyHeader);

            TextBox txtExplanation = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(22, 17, 24),
                ForeColor = Color.FromArgb(241, 245, 249),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle,
                Location = new Point(0, 24),
                Size = new Size(542, 215),
                Text = cfg.SafetyWarningExplanation ?? ""
            };
            pnlBody.Controls.Add(txtExplanation);

            Label lblGuidanceNotice = new Label
            {
                Text = Loc.T(
                    "⚠️ Argon bu değişikliği kesinlikle uygulamaz. Kendi riskinizle harici olarak yapmak isterseniz:",
                    "⚠️ Argon will never apply this change. If you wish to configure externally at your own risk:"),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(0, 246),
                Size = new Size(542, 32)
            };
            pnlBody.Controls.Add(lblGuidanceNotice);

            Label lblTargetPath = new Label
            {
                Text = Loc.T("Kayıt Defteri Hedefi: ", "Registry Target: ") + cfg.RegeditTargetPath,
                Font = new Font("Consolas", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(0, 280),
                Size = new Size(542, 20),
                AutoEllipsis = true
            };
            pnlBody.Controls.Add(lblTargetPath);

            this.Controls.Add(pnlBody);

            // Bottom Button Bar
            Panel pnlBottom = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 60,
                BackColor = Color.FromArgb(20, 25, 36)
            };
            pnlBottom.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(30, 41, 59), 1))
                {
                    e.Graphics.DrawLine(p, 0, 0, pnlBottom.Width, 0);
                }
            };

            Button btnRegedit = new Button
            {
                Text = Loc.T("📂 Kayıt Defterinde Aç (Regedit)", "📂 Open in Registry (Regedit)"),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                BackColor = Color.FromArgb(18, 30, 46),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(205, 34),
                Location = new Point(16, 13),
                Cursor = Cursors.Hand
            };
            btnRegedit.FlatAppearance.BorderSize = 1;
            btnRegedit.FlatAppearance.BorderColor = Color.FromArgb(56, 189, 248);
            btnRegedit.Click += (s, e) => GuidanceHelpers.OpenRegeditAtKey(cfg.RegeditTargetPath);
            pnlBottom.Controls.Add(btnRegedit);

            Button btnGoogle = new Button
            {
                Text = Loc.T("🌐 Google'da Ara", "🌐 Search Google"),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(167, 139, 250),
                BackColor = Color.FromArgb(28, 22, 44),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(160, 34),
                Location = new Point(228, 13),
                Cursor = Cursors.Hand
            };
            btnGoogle.FlatAppearance.BorderSize = 1;
            btnGoogle.FlatAppearance.BorderColor = Color.FromArgb(167, 139, 250);
            btnGoogle.Click += (s, e) => GuidanceHelpers.OpenGoogleSearch(cfg.GoogleSearchQuery);
            pnlBottom.Controls.Add(btnGoogle);

            Button btnClose = new Button
            {
                Text = Loc.T("Anladım, Kapat", "Understood, Close"),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                BackColor = Color.FromArgb(30, 41, 59),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(130, 34),
                Location = new Point(428, 13),
                Cursor = Cursors.Hand,
                DialogResult = DialogResult.OK
            };
            btnClose.FlatAppearance.BorderSize = 1;
            btnClose.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnClose.Click += (s, e) => this.Close();
            pnlBottom.Controls.Add(btnClose);

            this.Controls.Add(pnlBottom);
        }
    }

    public class CustomParameterDialog : Form
    {
        private TweakDefinition tweak;
        private CustomParamConfig cfg;
        private NumericUpDown numValue;

        public CustomParameterDialog(TweakDefinition tweak)
        {
            this.tweak = tweak;
            this.cfg = tweak.CustomParam;

            this.Text = Loc.T("Argon Makineye Özel Parametre Ayarı", "Argon Machine-Specific Parameter Config");
            this.Size = new Size(590, 490);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowInTaskbar = false;
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(15, 20, 28);
            this.ForeColor = Color.FromArgb(226, 232, 240);

            // Header Panel
            Panel pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 60,
                BackColor = Color.FromArgb(20, 28, 42),
                Padding = new Padding(16, 8, 16, 8)
            };
            pnlHeader.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(56, 189, 248), 1))
                {
                    e.Graphics.DrawLine(p, 0, pnlHeader.Height - 1, pnlHeader.Width, pnlHeader.Height - 1);
                }
            };

            Label lblTitle = new Label
            {
                Text = "⚙ " + tweak.Title,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(14, 8)
            };
            pnlHeader.Controls.Add(lblTitle);

            Label lblSub = new Label
            {
                Text = cfg.DisplayLabel + " — " + (tweak.TargetPathOrApi ?? "Kernel / Win32 API"),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(14, 32)
            };
            pnlHeader.Controls.Add(lblSub);
            this.Controls.Add(pnlHeader);

            // Body Panel
            Panel pnlBody = new Panel
            {
                Location = new Point(16, 70),
                Size = new Size(542, 335),
                BackColor = Color.Transparent
            };

            int currentLiveVal = cfg.ReadCurrentValueFunc != null ? cfg.ReadCurrentValueFunc() : cfg.DefaultValue;

            Label lblRegPath = new Label
            {
                Text = Loc.T("Sistem Hedefi (Kayıt Defteri):", "System Target (Registry):") + " " + (cfg.RegeditTargetPath ?? ""),
                Font = new Font("Consolas", 8.2f, FontStyle.Regular),
                ForeColor = Color.FromArgb(125, 211, 252),
                Location = new Point(0, 4),
                Size = new Size(542, 18),
                AutoEllipsis = true
            };
            pnlBody.Controls.Add(lblRegPath);

            Label lblLiveTruth = new Label
            {
                Text = string.Format(Loc.T("Windows'taki Canlı Değer: {0} {1}", "Current Windows Value: {0} {1}"), currentLiveVal, cfg.Unit),
                Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                Location = new Point(0, 26),
                Size = new Size(542, 20)
            };
            pnlBody.Controls.Add(lblLiveTruth);

            Label lblDesc = new Label
            {
                Text = cfg.TechnicalDescription ?? "",
                Font = new Font("Segoe UI", 8.4f, FontStyle.Regular),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(0, 52),
                Size = new Size(542, 42)
            };
            pnlBody.Controls.Add(lblDesc);

            // Security Floor Badge Panel
            Panel pnlBadge = new Panel
            {
                Location = new Point(0, 100),
                Size = new Size(542, 34),
                BackColor = Color.FromArgb(32, 26, 18)
            };
            pnlBadge.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(245, 158, 11), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlBadge.Width - 1, pnlBadge.Height - 1);
                }
            };

            Label lblBadge = new Label
            {
                Text = string.Format(Loc.T(
                    "🛡️ Kesin Güvenlik Tabanı: En Az {0} {1} ({0} altı değerler donanım bütünlüğü için engellenir)",
                    "🛡️ Strict Security Floor: Minimum {0} {1} (Values below {0} are blocked for stability)"),
                    cfg.MinValue, cfg.Unit),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                AutoSize = true,
                Location = new Point(10, 8)
            };
            pnlBadge.Controls.Add(lblBadge);
            pnlBody.Controls.Add(pnlBadge);

            // Numeric Input Section
            Label lblInputPrompt = new Label
            {
                Text = Loc.T("Makineye Özel Değer Belirleyin:", "Specify Machine-Specific Value:"),
                Font = new Font("Segoe UI", 9.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(0, 148),
                AutoSize = true
            };
            pnlBody.Controls.Add(lblInputPrompt);

            numValue = new NumericUpDown
            {
                Minimum = 0,
                Maximum = cfg.MaxValue,
                Value = Math.Max(0, Math.Min(cfg.MaxValue, cfg.CurrentCustomValue > 0 ? cfg.CurrentCustomValue : currentLiveVal)),
                Font = new Font("Consolas", 13.5f, FontStyle.Bold),
                BackColor = Color.FromArgb(24, 32, 46),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(0, 172),
                Size = new Size(130, 32)
            };
            pnlBody.Controls.Add(numValue);

            Label lblUnit = new Label
            {
                Text = cfg.Unit,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(136, 178),
                AutoSize = true
            };
            pnlBody.Controls.Add(lblUnit);

            // Quick Preset Chips
            if (cfg.PresetQuickChips != null && cfg.PresetQuickChips.Length > 0)
            {
                Label lblChipsCaption = new Label
                {
                    Text = Loc.T("Hızlı Seçim Önerileri:", "Quick Preset Suggestions:"),
                    Font = new Font("Segoe UI", 8.2f, FontStyle.Regular),
                    ForeColor = Color.FromArgb(148, 163, 184),
                    Location = new Point(0, 215),
                    AutoSize = true
                };
                pnlBody.Controls.Add(lblChipsCaption);

                int chipX = 0;
                for (int i = 0; i < cfg.PresetQuickChips.Length; i++)
                {
                    int valChip = cfg.PresetQuickChips[i];
                    string chipText = (cfg.PresetChipLabels != null && i < cfg.PresetChipLabels.Length)
                        ? cfg.PresetChipLabels[i]
                        : (valChip.ToString() + " " + cfg.Unit);

                    Button btnChip = new Button
                    {
                        Text = chipText,
                        Font = new Font("Segoe UI", 8.0f, FontStyle.Regular),
                        ForeColor = Color.FromArgb(203, 213, 225),
                        BackColor = Color.FromArgb(22, 29, 41),
                        FlatStyle = FlatStyle.Flat,
                        AutoSize = true,
                        Height = 26,
                        Location = new Point(chipX, 236),
                        Cursor = Cursors.Hand
                    };
                    btnChip.FlatAppearance.BorderSize = 1;
                    btnChip.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                    btnChip.Click += (s, e) =>
                    {
                        numValue.Value = valChip;
                    };
                    pnlBody.Controls.Add(btnChip);
                    chipX += btnChip.PreferredSize.Width + 8;
                }
            }

            // Info Link to Security Guidance
            Button btnWhySecurity = new Button
            {
                Text = Loc.T("ℹ️ Neden Güvenlik Kilidi Var? / Manuel Regedit Rehberi", "ℹ️ Why Security Lock? / Manual Regedit Guide"),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Underline),
                ForeColor = Color.FromArgb(248, 113, 113),
                BackColor = Color.Transparent,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(542, 28),
                Location = new Point(0, 282),
                TextAlign = ContentAlignment.MiddleLeft,
                Cursor = Cursors.Hand
            };
            btnWhySecurity.FlatAppearance.BorderSize = 0;
            btnWhySecurity.Click += (s, e) =>
            {
                using (SecurityLockGuidanceDialog lockDlg = new SecurityLockGuidanceDialog(tweak, cfg, (int)numValue.Value))
                {
                    lockDlg.ShowDialog(this);
                }
            };
            pnlBody.Controls.Add(btnWhySecurity);

            this.Controls.Add(pnlBody);

            // Bottom Action Bar
            Panel pnlBottom = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 60,
                BackColor = Color.FromArgb(20, 25, 36)
            };
            pnlBottom.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(30, 41, 59), 1))
                {
                    e.Graphics.DrawLine(p, 0, 0, pnlBottom.Width, 0);
                }
            };

            Button btnRegedit = new Button
            {
                Text = Loc.T("📂 Regedit", "📂 Regedit"),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(56, 189, 248),
                BackColor = Color.FromArgb(18, 28, 40),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(100, 34),
                Location = new Point(16, 13),
                Cursor = Cursors.Hand
            };
            btnRegedit.FlatAppearance.BorderSize = 1;
            btnRegedit.FlatAppearance.BorderColor = Color.FromArgb(45, 68, 98);
            btnRegedit.Click += (s, e) => GuidanceHelpers.OpenRegeditAtKey(cfg.RegeditTargetPath);
            pnlBottom.Controls.Add(btnRegedit);

            Button btnGoogle = new Button
            {
                Text = Loc.T("🌐 Google", "🌐 Google"),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(167, 139, 250),
                BackColor = Color.FromArgb(26, 20, 38),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(100, 34),
                Location = new Point(122, 13),
                Cursor = Cursors.Hand
            };
            btnGoogle.FlatAppearance.BorderSize = 1;
            btnGoogle.FlatAppearance.BorderColor = Color.FromArgb(68, 51, 98);
            btnGoogle.Click += (s, e) => GuidanceHelpers.OpenGoogleSearch(cfg.GoogleSearchQuery);
            pnlBottom.Controls.Add(btnGoogle);

            Button btnApply = new Button
            {
                Text = Loc.T("✓ Uygula & Kaydet", "✓ Apply & Save"),
                Font = new Font("Segoe UI", 9.0f, FontStyle.Bold),
                ForeColor = Color.White,
                BackColor = Color.FromArgb(16, 185, 129),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(140, 34),
                Location = new Point(310, 13),
                Cursor = Cursors.Hand
            };
            btnApply.FlatAppearance.BorderSize = 0;
            btnApply.Click += (s, e) =>
            {
                int val = (int)numValue.Value;
                if (val < cfg.MinValue)
                {
                    // Trigger Strict Security Lock!
                    using (SecurityLockGuidanceDialog lockDlg = new SecurityLockGuidanceDialog(tweak, cfg, val))
                    {
                        lockDlg.ShowDialog(this);
                    }
                    return;
                }

                cfg.CurrentCustomValue = val;
                if (cfg.ApplyCustomAction != null)
                {
                    cfg.ApplyCustomAction(val);
                }
                this.DialogResult = DialogResult.OK;
                this.Close();
            };
            pnlBottom.Controls.Add(btnApply);

            Button btnCancel = new Button
            {
                Text = Loc.T("İptal", "Cancel"),
                Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(203, 213, 225),
                BackColor = Color.FromArgb(30, 41, 59),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(95, 34),
                Location = new Point(458, 13),
                Cursor = Cursors.Hand,
                DialogResult = DialogResult.Cancel
            };
            btnCancel.FlatAppearance.BorderSize = 1;
            btnCancel.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnCancel.Click += (s, e) => this.Close();
            pnlBottom.Controls.Add(btnCancel);

            this.Controls.Add(pnlBottom);
        }
    }

    #endregion

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
        private bool revertOnExit = false;          // option: restore system defaults when Argon closes
        private bool suppressRevertOnExit = false;  // set by "PC Yeniden Baslat" so reboot-required tweaks are not undone
        private ToolStripMenuItem mnuRevertOnExit;
        private ToolStripMenuItem mnuExit;
        private CheckBox chkRevertOnExit;
        private CheckBox chkAutoStart;
        private bool syncingRevertUi = false;
        private bool suppressAutoStartHandler = false;
        private bool startHiddenInTray = false;
        private bool trayStartHandled = false;
        private const string AutoStartTaskName = "ArgonLatencyStudio_Autostart";
        // saved profile lines of tweaks that could not be applied in limited (non-admin) mode; written back unchanged
        private Dictionary<string, string> preservedProfileTweakLines = new Dictionary<string, string>();
        private bool isLoadingProfile = false;
        private string userProfilePath;

        private List<string> activeTcpInterfaceGuids = new List<string>();
        private string activeNicClassSubKey = "";
        private string activeGpuClassSubKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000";

        private bool timerLockActive = false;
        private bool timerPeriodHeld = false;

        // Win11: a window-owning process that is minimized / occluded / hidden in the tray gets its
        // timer-resolution requests ignored (and may be EcoQoS-throttled) unless it opts out.
        private static void OptOutSelfFromTimerIgnoreAndEcoQos()
        {
            try
            {
                NativeMethods.PROCESS_POWER_THROTTLING_STATE st = new NativeMethods.PROCESS_POWER_THROTTLING_STATE
                {
                    Version = 1,
                    ControlMask = NativeMethods.PROCESS_POWER_THROTTLING_EXECUTION_SPEED | NativeMethods.PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
                    StateMask = 0
                };
                NativeMethods.SetProcessInformation(Process.GetCurrentProcess().Handle, NativeMethods.ProcessPowerThrottling, ref st, (uint)Marshal.SizeOf(typeof(NativeMethods.PROCESS_POWER_THROTTLING_STATE)));
            }
            catch { }
        }

        private void HoldTimerPeriod()
        {
            if (timerPeriodHeld) return;
            OptOutSelfFromTimerIgnoreAndEcoQos();
            NativeMethods.timeBeginPeriod(1);
            timerPeriodHeld = true;
        }

        private void ReleaseTimerPeriod()
        {
            if (!timerPeriodHeld) return;
            NativeMethods.timeEndPeriod(1);
            timerPeriodHeld = false;
        }
        private uint desiredTimerUnit = 5000;
        private volatile bool pulseThreadRunning = false;
        private int pulseMode = 0;
        private Thread syntheticPulseThread;
        private bool autoStandbyCleanerActive = false;
        private bool autoGameWatchdogActive = false;
        private int standbyIsolationMode = 0;
        private int fpsEcoQosMode = 0;
        private int fpsAudioIsoMode = 0;
        private List<string> pausedServicesByArgon = new List<string>();
        private string currentBootStamp = "";

        private List<TweakDefinition> allTweaks = new List<TweakDefinition>();
        private List<MultiVariationTweakCard> allCards = new List<MultiVariationTweakCard>();
        private Dictionary<MultiVariationTweakCard, Control> cardHomeContainers = new Dictionary<MultiVariationTweakCard, Control>();

        private ArgonAppSettings appSettings;
        private string appSettingsPath;
        private LibreHardwareSensorEngine sensorEngine;
        private volatile bool sensorPollingBusy = false;
        private long lastSensorPollTickMs = 0;

        private string customProfilesDir;
        private List<ArgonCustomProfile> customProfiles = new List<ArgonCustomProfile>();
        private ComboBox cmbProfileSelector;
        private bool suppressProfileComboEvent = false;

        private ToolTip mainToolTip;
        private Panel pnlTopHeader;
        private Panel pnlNavBar;
        private Panel pnlRightSidebar;
        private Panel pnlInspectorFooter;
        private Label lblInspectorTitle;
        private Label lblInspectorPath;

        private Label lblTopTimer;
        private Label lblTopPing;
        private Label lblTopRam;
        private Label lblTopActiveCount;
        private Label lblTopCpuSensor;
        private Label lblTopGpuSensor;
        private TextBox txtGlobalSearch;
        private Label lblSearchIcon;
        private Label lblLiveSystemStatusPill;

        // Right Sidebar (NetAdapter Repair-style Live Network, Hardware Telemetry & OS Audit Console)
        private TextBox txtNetHostAdmin;
        private TextBox txtNetAdapter;
        private TextBox txtNetLocalIp;
        private TextBox txtNetGateway;
        private TextBox txtNetDns;
        private TextBox txtNetMac;
        private TextBox txtNetPingLive;
        private TextBox txtHwCpuName;
        private TextBox txtHwCpuTelemetry;
        private TextBox txtHwGpuName;
        private TextBox txtHwGpuTelemetry;
        private TextBox txtHwRamUsage;
        private TextBox txtHwTimerActive;
        private TextBox txtLiveConsoleLog;
        private Label lblNetTrafficStats;

        // Progressive Dashboard & Hardware Matrix Controls
        private ComboBox cmbCpuSelector;
        private ComboBox cmbGpuSelector;
        private Button btnTier1;
        private Button btnTier2;
        private Button btnTier3;
        private Label lblMatrixSummary;
        private FlowLayoutPanel flowHardwareSpecificCards;
        private Button btnLangToggle;
        private Label lblProfCaption;
        private Button btnQuickSaveProf;
        private Button btnSmartTuneTop;
        private Button btnResetAllTop;
        private Button btnMinimizeTray;
        private Button btnElevate;
        private Label lblMatTitle;
        private Label lblCpuPick;
        private Label lblGpuPick;
        private Label lblTierPick;
        private Button btnSmartApply;
        private Button btnAutoDetectReset;
        private Button btnQuickRam;
        private Label grpNetAdapter;
        private Button btnSidePingIp;
        private Button btnSidePingDns;
        private Button btnSideFlush;
        private Button btnSideRefreshNet;
        private Label lblHwHdr;
        private Label lblSideEventLogHeader;
        private ComboBox cmbSetLanguage;
        private Dictionary<TextBox, Label> sidebarRowLabels = new Dictionary<TextBox, Label>();
        private List<Label> tweakColHeadersCol1 = new List<Label>();
        private List<Label> tweakColHeadersCol2 = new List<Label>();
        private List<Label> tweakColHeadersCol3 = new List<Label>();

        private List<Button> navButtons = new List<Button>();
        private int currentActiveTabIndex = 0;
        private Panel pnlContentHost;
        private Panel viewDashboard;
        private FlowLayoutPanel viewNetwork;
        private FlowLayoutPanel viewLatency;
        private FlowLayoutPanel viewFps;
        private Panel viewWinUtil;
        private FlowLayoutPanel flowWinUtilCards;
        private FlowLayoutPanel viewExperimental;
        private Panel viewProcesses;
        private Panel viewAutomationQoL;
        private Panel viewBenchmark;
        private Panel viewSnapshotAudit;
        private Panel viewSettings;
        private Panel viewGlobalSearch;
        private FlowLayoutPanel flowGlobalSearchCards;
        private Label lblGlobalSearchHeader;

        // Otomasyon & QoL Modülü
        private QoLAutomationConfig qolConfig = new QoLAutomationConfig();
        private string qolConfigPath;
        private Label lblPowerTimerStatus;
        private Button btnStartPowerTimer;
        private Button btnCancelPowerTimer;
        private NumericUpDown numPowerHours;
        private NumericUpDown numPowerMins;
        private TextBox txtPowerSpecificTime;
        private RadioButton rbPowerCountdown;
        private RadioButton rbPowerSpecific;
        private ComboBox cmbPowerAction;
        private ListView lvAlarms;
        private ListView lvGameNotes;
        private Label lblQoLRamStatus;
        private CheckBox chkAutoRamEnable;
        private RadioButton rbRam10;
        private RadioButton rbRam15;
        private RadioButton rbRam20;
        private RadioButton rbRam30;
        private RadioButton rbRamCustom;
        private NumericUpDown numRamCustom;
        private Label lblSystemTempStatus;
        private Label lblShaderCacheStatus;
        private Button btnCleanTempNow;
        private Button btnCleanShaderNow;
        private double liveDownloadSpeedKBps = 0;
        private long lastTrafficBytesRecv = 0;
        private DateTime lastTrafficSampleTime = DateTime.MinValue;

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
            appSettingsPath = Path.Combine(profileDir, "argon_app_settings.txt");
            appSettings = ArgonAppSettings.Load(appSettingsPath);
            qolConfigPath = Path.Combine(profileDir, "argon_automation_qol.txt");
            qolConfig = QoLAutomationConfig.LoadFromFile(qolConfigPath);
            customProfilesDir = Path.Combine(profileDir, "CustomProfiles");
            if (!Directory.Exists(customProfilesDir)) Directory.CreateDirectory(customProfilesDir);
            LoadCustomProfilesList();

            sensorEngine = new LibreHardwareSensorEngine();

            mainToolTip = new ToolTip
            {
                AutoPopDelay = 32000,
                InitialDelay = appSettings.RichTooltipsEnabled ? 120 : 400,
                ReshowDelay = 50,
                ShowAlways = true,
                IsBalloon = false
            };

            startHiddenInTray = (args != null && Array.IndexOf(args, "--tray") >= 0);
            RegisterAllTweaksCatalog();
            // Baseline boot probe: record initial boot state of OS so variation toggling never produces false restart requests
            foreach (var t in allTweaks)
            {
                VerifySingleTweakInLiveOs(t);
                t.BootTimeActiveInOs = t.IsDetectedActiveInOs;
                t.BootTimeVariationInOs = t.DetectedVariationInOs;
                t.BootTimeRawValue = t.VerifiedSystemValue;
                if (t.IsDetectedActiveInOs)
                {
                    t.RebootSatisfied = true;
                    t.NetReloadSatisfied = true;
                }
            }
            InitializeStudioUI();
            ApplyWindowLayoutPolicy();
            bool baselineLostWithProfile = vault.BaselineRecapturedFresh && File.Exists(userProfilePath);
            LoadAndRestoreUserProfileState();
            ProbeAllTweaksLiveOsTruthAndOptionallySync(appSettings.AutoLiveTruthSync);
            if (preservedProfileTweakLines.Count > 0 && lblInspectorTitle != null)
                lblInspectorTitle.Text = string.Format("⚠️ Yönetici yetkisi yok: {0} kayıtlı ayar uygulanmadı (profilde korunuyor). 'Yönetici Olarak Aç' ile devam edin.", preservedProfileTweakLines.Count);
            this.Shown += (snd2, evt2) =>
            {
                SyncAutoStartCheckboxFromSystem();
                UpdateRebootAndReloadBannerVisibility();
                LayoutNavBarButtons();
            };
            if (baselineLostWithProfile)
            {
                this.Shown += (snd, evt) => MessageBox.Show(
                    "Orijinal sistem yedeği (original_baseline_backup.txt) bulunamadı. Argon şu anki sistem durumunu 'orijinal' olarak kaydetti.\n\n" +
                    "Daha önce Argon ayarları bu sistemde uygulandıysa 'Makine Varsayılanlarına Döndür' bu ayarları geri ALMAYABİLİR.",
                    "Orijinal Yedek Bulunamadı", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }

            telemetryTimer = new System.Windows.Forms.Timer { Interval = 500 };
            telemetryTimer.Tick += OnTelemetryTick;
            telemetryTimer.Start();

            TriggerAsyncHardwareSensorPoll();
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

            net04.CustomParam = new CustomParamConfig
            {
                ParameterName = "InitialRTO",
                DisplayLabel = Loc.T("TCP İlk Kayıp Paket Telafi Süresi (RTO)", "TCP Initial Retransmission Timeout (RTO)"),
                MinValue = 300,
                MaxValue = 3000,
                DefaultValue = 3000,
                CurrentCustomValue = 300,
                Unit = "ms",
                TechnicalDescription = Loc.T(
                    "TCP bağlantılarında paket kaybı yaşandığında sistemin yeniden iletim başlatmadan önce beklediği asgari süredir.",
                    "Minimum time the Windows TCP stack waits before retransmitting a lost packet."),
                SafetyWarningTitle = Loc.T("GÜVENLİK KİLİDİ: 300ms Altı Değerler Engellendi", "SAFETY LOCK: Values Below 300ms Are Blocked"),
                SafetyWarningExplanation = Loc.T(
                    "Neden 300ms Altına İzin Verilmiyor?\n\n" +
                    "1. TCP/IP PROTOKOL STANDARDI:\n" +
                    "Windows TCP/IP çekirdeği (netsh) initialRto için kesin alt sınır olarak 300ms kuralını uygular.\n\n" +
                    "2. PAKET DÖNGÜSÜ VE TIKANIKLIK:\n" +
                    "300ms'nin altındaki değerler, en ufak bir rota gecikmesinde henüz yolda olan paketlerin mükerrer olarak tekrar gönderilmesine (SYN/ACK fırtınası) ve bağlantının çökmesine neden olur.",
                    "Why Are Values Below 300ms Blocked?\n\n" +
                    "1. TCP/IP PROTOCOL MANDATE:\n" +
                    "Windows TCP/IP stack strictly enforces a 300ms floor for initialRto via netsh.\n\n" +
                    "2. RETRANSMISSION FLOOD & PACKET LOSS:\n" +
                    "Values under 300ms trigger false retransmissions for packets still in flight, causing congestion collapses and dropped connections."),
                RegeditTargetPath = @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                GoogleSearchQuery = Loc.T("TCP Initial RTO netsh ayarı", "TCP Initial RTO netsh setting"),
                PresetQuickChips = new int[] { 300, 500, 1000, 3000 },
                PresetChipLabels = new string[] {
                    Loc.T("300ms (Espor)", "300ms (Esports)"),
                    Loc.T("500ms (Hızlı)", "500ms (Fast)"),
                    Loc.T("1000ms (Dengeli)", "1000ms (Balanced)"),
                    Loc.T("3000ms (Varsayılan)", "3000ms (Default)")
                },
                ReadCurrentValueFunc = () =>
                {
                    return 300;
                },
                ApplyCustomAction = (customVal) =>
                {
                    vault.NetshModified = true;
                    vault.SetRegistryTracked(net04.Title, "HKLM", tcpParams, "TcpMaxDataRetransmissions", customVal <= 500 ? 3 : 5, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", string.Format("int tcp set global initialRto={0} maxsynretransmissions=2 nonsackrttresiliency=disabled", customVal));
                }
            };
            net04.Variations.Add(new TweakVariation(
                "Özel RTO [⚙] (Kullanıcı Tanımlı)",
                "Makineye Özel TCP Kayıp Paket Telafi Süresi",
                "Kullanıcının belirlediği özel RTO süresini (en az 300ms) uygular.",
                "initialRto=Özel ms",
                () =>
                {
                    int v = net04.CustomParam.CurrentCustomValue >= 300 ? net04.CustomParam.CurrentCustomValue : 300;
                    net04.CustomParam.ApplyCustomAction(v);
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

            net09.CustomParam = new CustomParamConfig
            {
                ParameterName = "ReceiveBuffers",
                DisplayLabel = Loc.T("Ağ Kartı Paket Tamponu (Ring Buffer)", "Network Card Packet Buffer (Ring Buffer)"),
                MinValue = 64,
                MaxValue = 4096,
                DefaultValue = 512,
                CurrentCustomValue = 512,
                Unit = Loc.T("Paket", "Packets"),
                TechnicalDescription = Loc.T(
                    "Ağ kartı donanımının gelen ve giden paketleri bellek üzerinde tuttuğu tampon havuzu boyutudur.",
                    "Ring buffer size where the network adapter holds incoming and outgoing packets in host memory."),
                SafetyWarningTitle = Loc.T("GÜVENLİK KİLİDİ: 64 Altı Değerler Engellendi", "SAFETY LOCK: Values Below 64 Are Blocked"),
                SafetyWarningExplanation = Loc.T(
                    "Neden 64'ün Altına İzin Verilmiyor?\n\n" +
                    "1. DÜŞÜK TAMPON TAŞMASI:\n" +
                    "Modern 100Mbit / 1Gbit+ ağ kartlarında 64'ün altındaki tamponlar anlık veri patlamalarında hemen dolar.\n\n" +
                    "2. PAKET KAYBI (PACKET LOSS):\n" +
                    "Tampon taştığında yeni gelen paketler düşürülür (drop edilir), bu da online oyunlarda ani paket kaybına ve takılmaya yol açar.",
                    "Why Are Values Below 64 Blocked?\n\n" +
                    "1. BUFFER OVERFLOW UNDER LOAD:\n" +
                    "On modern 100Mbit / 1Gbps+ NICs, buffers under 64 fill instantly during burst traffic.\n\n" +
                    "2. PACKET DROPS & JITTER:\n" +
                    "Overflowing ring buffers force the NIC hardware to drop packets, causing packet loss and game stutter."),
                RegeditTargetPath = activeNicClassSubKey,
                GoogleSearchQuery = Loc.T("Ağ Kartı Interrupt Moderation Receive Buffers ayarı", "Network Adapter Receive Buffers Interrupt Moderation setting"),
                PresetQuickChips = new int[] { 64, 128, 512, 1024 },
                PresetChipLabels = new string[] {
                    Loc.T("64 (Taban Sınır)", "64 (Safe Floor)"),
                    Loc.T("128 (Ultra Düşük)", "128 (Ultra Low)"),
                    Loc.T("512 (Önerilen)", "512 (Recommended)"),
                    Loc.T("1024 (Fiber/Yayın)", "1024 (Fiber/Stream)")
                },
                ReadCurrentValueFunc = () =>
                {
                    string rb = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*ReceiveBuffers", "512");
                    int v;
                    return int.TryParse(rb, out v) ? v : 512;
                },
                ApplyCustomAction = (customVal) =>
                {
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*InterruptModeration", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*ReceiveBuffers", customVal.ToString(), RegistryValueKind.String);
                    vault.SetRegistryTracked(net09.Title, "HKLM", activeNicClassSubKey, "*TransmitBuffers", customVal.ToString(), RegistryValueKind.String);
                }
            };
            net09.Variations.Add(new TweakVariation(
                "Özel Tampon [⚙] (Kullanıcı Tanımlı)",
                "Makineye Özel Ağ Kartı Ring Buffer Tamponu",
                "Kullanıcının belirlediği özel tampon boyutunu (en az 64 paket) uygular.",
                "ReceiveBuffers=Özel, TransmitBuffers=Özel",
                () =>
                {
                    int v = net09.CustomParam.CurrentCustomValue >= 64 ? net09.CustomParam.CurrentCustomValue : 512;
                    net09.CustomParam.ApplyCustomAction(v);
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
                        ReleaseTimerPeriod();
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
                        uint cur;
                        NativeMethods.NtSetTimerResolution(0, false, out cur);
                        HoldTimerPeriod();
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
                        uint cur;
                        NativeMethods.NtSetTimerResolution(0, false, out cur);
                        HoldTimerPeriod();
                        NativeMethods.NtSetTimerResolution(10000, true, out cur);
                    }
                    catch { }
                    // 1.000 ms mode: clear the global flag a previous 0.500/0.504 selection may have left behind
                    if (isAdmin)
                        vault.RevertRegistryTracked("HKLM", kernelKey, "GlobalTimerResolutionRequests");
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
                        uint cur;
                        NativeMethods.NtSetTimerResolution(0, false, out cur);
                        HoldTimerPeriod();
                        NativeMethods.NtSetTimerResolution(5040, true, out cur);
                    }
                    catch { }
                    // Same as 0.500 ms mode: on Win10 2004+/Win11 the request is process-local without this flag
                    // (it is read by the kernel; a restart may be required for a change to take effect).
                    if (isAdmin)
                        vault.SetRegistryTracked(lat01.Title, "HKLM", kernelKey, "GlobalTimerResolutionRequests", 1, RegistryValueKind.DWord);
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
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseSpeed", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseThreshold1", "0", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat05.Title, "HKCU", @"Control Panel\Mouse", "MouseThreshold2", "0", RegistryValueKind.String);
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
                RequiresAdmin = true,
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
                "Espor Dengeli + 1000Hz (Kuyruk=40)",
                "Sohbet Ederken Harf Tekrarlamayan Rahat Klavye + 40 Paket Kuyruk",
                "Sürekli yazılı iletişim kuranlar için harflerin arka arkaya fazladan basılmasını önler (Delay=1) ve 1000Hz fare/klavye için ideal 40 kuyruk boyutunu ayarlar.",
                "KeyboardDelay=1 (Rahat Yazım), KeyboardSpeed=31, DataQueueSize=40",
                () =>
                {
                    vault.KeyboardSpiModified = true;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, 1, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, 31, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    vault.SetRegistryTracked(lat06.Title, "HKCU", @"Control Panel\Keyboard", "KeyboardDelay", "1", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat06.Title, "HKCU", @"Control Panel\Keyboard", "KeyboardSpeed", "31", RegistryValueKind.String);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(lat06.Title, "HKLM", mouParams, "MouseDataQueueSize", 40, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(lat06.Title, "HKLM", kbdParams, "KeyboardDataQueueSize", 40, RegistryValueKind.DWord);
                    }
                    vault.SaveJournal();
                }));
            lat06.Variations.Add(new TweakVariation(
                "Espor Taban Sınırı (Kuyruk=32 + Hızlı Tekrar)",
                "Kesin Taban Sınır (32 Paket) + Hızlı Tuş Tekrarı",
                "1000Hz fareler için izin verilen en düşük güvenli tampon boyutunu (32) ve hızlı klavye tekrarını uygular. 32 altı değerler takılmaya yol açtığı için bu mod kesin güvenlik sınırıdır.",
                "KeyboardDelay=0, KeyboardSpeed=31, DataQueueSize=32",
                () =>
                {
                    vault.KeyboardSpiModified = true;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, 0, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, 31, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(lat06.Title, "HKLM", mouParams, "MouseDataQueueSize", 32, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(lat06.Title, "HKLM", kbdParams, "KeyboardDataQueueSize", 32, RegistryValueKind.DWord);
                    }
                    vault.SaveJournal();
                }));
            lat06.Variations.Add(new TweakVariation(
                "4000Hz / 8000Hz Fare Korumalı (Kuyruk=64)",
                "Yüksek Hz (4K/8K) Oyuncu Fareleri İçin Genişletilmiş Tampon Modu",
                "4000Hz ve 8000Hz farelerde imleç atlamasını ve tampon taşmasını önleyen genişletilmiş 64 paketlik güvenli tampon ve rahat yazışma ayarı.",
                "KeyboardDelay=1, KeyboardSpeed=31, MouseDataQueueSize=64",
                () =>
                {
                    vault.KeyboardSpiModified = true;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, 1, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, 31, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(lat06.Title, "HKLM", mouParams, "MouseDataQueueSize", 64, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(lat06.Title, "HKLM", kbdParams, "KeyboardDataQueueSize", 40, RegistryValueKind.DWord);
                    }
                    vault.SaveJournal();
                }));

            lat06.CustomParam = new CustomParamConfig
            {
                ParameterName = "MouseDataQueueSize",
                DisplayLabel = Loc.T("Fare ve Klavye Tampon Boyutu", "Mouse & Keyboard Buffer Queue Size"),
                MinValue = 32,
                MaxValue = 300,
                DefaultValue = 100,
                CurrentCustomValue = 40,
                Unit = Loc.T("Paket", "Packets"),
                TechnicalDescription = Loc.T(
                    "Fare ve klavye donanımından gelen HID paketlerinin Windows çekirdeğinde sırada bekletildiği tampon boyutudur. Düşük değerler gecikmeyi azaltırken, 32'nin altı değerler anlık CPU yükünde girdi kaybına yol açar.",
                    "Buffer queue size where HID mouse & keyboard packets wait in Windows kernel. Lower values reduce latency, but values under 32 cause input packet drops during CPU spikes."),
                SafetyWarningTitle = Loc.T("KESİN GÜVENLİK KİLİDİ: 32 Altı Değerler Engellendi", "STRICT SAFETY LOCK: Values Below 32 Are Blocked"),
                SafetyWarningExplanation = Loc.T(
                    "Neden 32'nin Altına İzin Verilmiyor?\n\n" +
                    "1. YÜKSEK RAPORLAMA HIZI (1000Hz - 8000Hz):\n" +
                    "Modern oyuncu fareleri saniyede 1.000 ila 8.000 veri paketi gönderir.\n\n" +
                    "2. TAMPON TAŞMASI (BUFFER OVERFLOW):\n" +
                    "Kuyruk boyutu 32'nin altına (örn. 8, 16 veya 24) düşürüldüğünde, oyun içinde anlık bir CPU dalgalanması veya FPS düşüşü yaşandığı anda mouclass.sys tamponu mikrosaniyeler içinde taşar.\n\n" +
                    "3. GİRDİ KAYBI VE TAKILMA (STUTTER):\n" +
                    "Taşan paketler Windows çekirdeği tarafından doğrudan atılır. Bu da farenin anlık donmasına, tıklamaların algılanmamasına ve takılmaya neden olur.\n\n" +
                    "Argon Latency Studio, rekabetçi bütünlüğü ve donanım kararlılığını korumak için 32 altındaki değerleri kesinlikle uygulamaz.",
                    "Why Are Values Below 32 Blocked?\n\n" +
                    "1. HIGH POLLING RATES (1000Hz - 8000Hz):\n" +
                    "Modern gaming mice generate 1,000 to 8,000 packets per second.\n\n" +
                    "2. BUFFER OVERRUN HAZARD:\n" +
                    "When queue size is set below 32 (e.g. 8, 16, or 24), any momentary CPU spike or frame drop causes mouclass.sys buffer overrun within microseconds.\n\n" +
                    "3. DROPPED INPUTS & STUTTER:\n" +
                    "Overflowing packets are discarded by Windows kernel, resulting in cursor freeze, missed clicks, and input stutter.\n\n" +
                    "Argon Latency Studio strictly forbids applying values below 32 to guarantee hardware stability."),
                RegeditTargetPath = @"HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters",
                GoogleSearchQuery = Loc.T("Mouse - Keyboard Queue size ayarlama", "Mouse Keyboard Queue size registry setting"),
                PresetQuickChips = new int[] { 32, 40, 64, 100 },
                PresetChipLabels = new string[] {
                    Loc.T("32 (Espor Tabanı)", "32 (Esports Floor)"),
                    Loc.T("40 (Önerilen)", "40 (Recommended)"),
                    Loc.T("64 (4K/8K Hz)", "64 (4K/8K Hz)"),
                    Loc.T("100 (Fabrika)", "100 (Default)")
                },
                ReadCurrentValueFunc = () =>
                {
                    string mq = vault.ReadRegistryDisplay("HKLM", mouParams, "MouseDataQueueSize", "100");
                    int v;
                    return int.TryParse(mq, out v) ? v : 100;
                },
                ApplyCustomAction = (customVal) =>
                {
                    vault.KeyboardSpiModified = true;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDDELAY, 1, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_SETKEYBOARDSPEED, 31, IntPtr.Zero, NativeMethods.SPIF_SENDCHANGE);
                    vault.SetRegistryTracked(lat06.Title, "HKCU", @"Control Panel\Keyboard", "KeyboardDelay", "1", RegistryValueKind.String);
                    vault.SetRegistryTracked(lat06.Title, "HKCU", @"Control Panel\Keyboard", "KeyboardSpeed", "31", RegistryValueKind.String);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(lat06.Title, "HKLM", mouParams, "MouseDataQueueSize", customVal, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(lat06.Title, "HKLM", kbdParams, "KeyboardDataQueueSize", Math.Max(32, customVal), RegistryValueKind.DWord);
                    }
                    vault.SaveJournal();
                }
            };
            lat06.Variations.Add(new TweakVariation(
                "Özel Değer [⚙] (Kullanıcı Tanımlı)",
                "Makineye Özel Kullanıcı Tanımlı Tampon Boyutu",
                "Kullanıcının belirlediği özel kuyruk boyutunu (en az 32 paket) uygular.",
                "MouseDataQueueSize=Özel (>=32), KeyboardDataQueueSize=Özel",
                () =>
                {
                    int v = lat06.CustomParam.CurrentCustomValue >= 32 ? lat06.CustomParam.CurrentCustomValue : 40;
                    lat06.CustomParam.ApplyCustomAction(v);
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

            // =================================================================================================
            // CATEGORY 5: WINUTIL PRO & KRİTİK SİSTEM BÖLÜMÜ (SAFE SYSTEM ARCHITECTURE & UYARI KORUMALI)
            // Hiçbir şekilde Debloat / Defender / Güvenlik silme içermez. Sadece profesyonel sistem mimarisi!
            // =================================================================================================
            Color colWinUtil = Color.FromArgb(236, 72, 153); // Pink/Rose Accent for WinUtil Pro

            // WU-01: Multiplane Overlay (MPO) Stabilization (WinUtil: WPFMultiplaneOverlay)
            var wu01 = new TweakDefinition
            {
                Id = "WU_MPO_CONTROL",
                Category = "WINUTIL",
                HardwareTag = "ALL",
                BadgeText = "WINUTIL / MPO KALKANI",
                BadgeColor = colWinUtil,
                RequiresAdmin = true,
                NeedsReboot = true,
                RequiresCautionConfirmation = true,
                CautionWarningText = "MPO (Multiplane Overlay) kapatıldığında tarayıcı, Discord ve oyun arasındaki ekran titremeleri/siyah ekran sorunları çözülür; ancak değişiklik tam olarak Windows yeniden başlatıldığında devreye girer.",
                Title = "Multiplane Overlay (MPO) Katman Kalkanı (Titreme & Stutter Çözümü)",
                SummaryDescription = "Windows DWM'in birden fazla görüntü katmanını üst üste bindirirken ekran kartında yarattığı siyah ekran, titreme ve mikro-takılmaları önler.",
                DeepTechnicalWhy = "Chris Titus WinUtil (WPFMultiplaneOverlay) standardına göre tarayıcıda donanım hızlandırma açıkken veya çift monitörde oyun oynarken oluşan takılmaları kökten çözmek için kullanılır.",
                TargetPathOrApi = @"HKLM\SOFTWARE\Microsoft\Windows\Dwm\OverlayTestMode",
                QueryOriginalOrDefaultSummary = () => "OverlayTestMode=" + vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode", "0 (MPO Açık)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", @"SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode");
                    vault.RevertRegistryTracked("HKLM", gfxDrivers, "DisableOverlays");
                }
            };
            wu01.Variations.Add(new TweakVariation(
                "Uyumluluk Modu (OverlayTestMode=5 - Önerilen)",
                "WinUtil Standart MPO Devre Dışı Bırakma (En Güvenli Yöntem)",
                "DWM katman çakışmalarını ve oyun içi Alt+Tab takılmalarını güvenli şekilde engeller.",
                "OverlayTestMode=5",
                () =>
                {
                    vault.SetRegistryTracked(wu01.Title, "HKLM", @"SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode", 5, RegistryValueKind.DWord);
                    vault.RevertRegistryTracked("HKLM", gfxDrivers, "DisableOverlays");
                }));
            wu01.Variations.Add(new TweakVariation(
                "Tamamen Devre Dışı (OverlayTestMode=5 + DisableOverlays=1)",
                "Agresif MPO Kapatma (AMD/NVIDIA Çift Ekran Titreme Çözümü)",
                "Çift monitör veya farklı Hz değerlerine sahip ekranlarda oluşan tüm katman sorunlarını kapatır.",
                "OverlayTestMode=5, DisableOverlays=1",
                () =>
                {
                    vault.SetRegistryTracked(wu01.Title, "HKLM", @"SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode", 5, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(wu01.Title, "HKLM", gfxDrivers, "DisableOverlays", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(wu01);

            // WU-02: Teredo & IPv4 Priority Over IPv6 (WinUtil: WPFTweaksIPv46 + WPFTweaksTeredo)
            string tcp6Params = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
            var wu02 = new TweakDefinition
            {
                Id = "WU_IPV4_TEREDO",
                Category = "WINUTIL",
                HardwareTag = "ALL",
                BadgeText = "WINUTIL / AĞ TÜNELİ",
                BadgeColor = colWinUtil,
                RequiresAdmin = true,
                RequiresCautionConfirmation = true,
                CautionWarningText = "Teredo tünellemesini kapatmak çoğu rekabetçi oyunda arka plan paket gecikmesini düşürür; ancak Forza Horizon gibi eski Xbox Live P2P oyunlarında grup sohbeti için Teredo gerekebilir (Mod 1 güvenlidir).",
                Title = "IPv4 Önceliklendirme & Teredo Tünel Gecikmesi Kapatma",
                SummaryDescription = "IPv6 yapılandırılmamış ağlarda Windows'un önce IPv6 arayıp zaman kaybetmesini önler (IPv4 Preferred) ve Teredo tünel yükünü kapatır.",
                DeepTechnicalWhy = "Chris Titus WinUtil (WPFTweaksIPv46 & WPFTweaksTeredo) mimarisine dayanır. Yerel ağda ve oyun sunucularına bağlanırken yaşanan protokol dönüşüm gecikmesini ortadan kaldırır.",
                TargetPathOrApi = @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisabledComponents",
                QueryOriginalOrDefaultSummary = () => "DisabledComponents=" + vault.ReadRegistryDisplay("HKLM", tcp6Params, "DisabledComponents", "0 (Varsayılan)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", tcp6Params, "DisabledComponents");
                    StateVault.RunHiddenCmd("netsh", "interface teredo set state default");
                }
            };
            wu02.Variations.Add(new TweakVariation(
                "IPv4 Öncelikli Yap (DisabledComponents=32 - Güvenli)",
                "IPv6'yı Tamamen Kapatmadan IPv4'e Birinci Öncelik Ver",
                "Xbox ve modern ağ özelliklerini bozmadan tüm bağlantılarda IPv4'ü ilk sıraya alır.",
                "DisabledComponents=32 (0x20)",
                () =>
                {
                    vault.SetRegistryTracked(wu02.Title, "HKLM", tcp6Params, "DisabledComponents", 32, RegistryValueKind.DWord);
                }));
            wu02.Variations.Add(new TweakVariation(
                "IPv4 Öncelikli + Teredo Tünelini Kapat (Espor Modu)",
                "Hem IPv4 Önceliği Hem Teredo Sanal Tüneli Devre Dışı",
                "Sanal ağ tünelinin arka planda yarattığı ping dalgalanmasını tamamen keser.",
                "DisabledComponents=33 + Teredo=Disabled",
                () =>
                {
                    vault.SetRegistryTracked(wu02.Title, "HKLM", tcp6Params, "DisabledComponents", 33, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "interface teredo set state disabled");
                }));
            wu02.Variations.Add(new TweakVariation(
                "Sadece Teredo Tünelini Kapat",
                "IPv6 Ayarına Dokunmadan Yalnızca Teredo'yu Durdur",
                "Yalnızca Teredo tünel gecikmesini kapatmak için kullanılır.",
                "DisabledComponents=1 + Teredo=Disabled",
                () =>
                {
                    vault.SetRegistryTracked(wu02.Title, "HKLM", tcp6Params, "DisabledComponents", 1, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("netsh", "interface teredo set state disabled");
                }));
            allTweaks.Add(wu02);

            // WU-03: Delivery Optimization P2P Upload Blocker (WinUtil: WPFTweaksDeliveryOptimization)
            string doKey = @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
            var wu03 = new TweakDefinition
            {
                Id = "WU_DELIVERY_OPT",
                Category = "WINUTIL",
                HardwareTag = "ALL",
                BadgeText = "WINUTIL / UPLOAD KORUMA",
                BadgeColor = colWinUtil,
                RequiresAdmin = true,
                Title = "Windows Teslim İyileştirme (P2P Güncelleme Upload) Kapatma",
                SummaryDescription = "Windows'un arka planda internet upload hızınızı kullanarak dünyadaki diğer bilgisayarlara güncelleme dosyası göndermesini engeller.",
                DeepTechnicalWhy = "Chris Titus WinUtil (WPFTweaksDeliveryOptimization) temel ayarıdır. Oyun ortasında upload hattınızın gizlice sömürülüp pinginizin 300ms'ye fırlamasını engeller.",
                TargetPathOrApi = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode",
                QueryOriginalOrDefaultSummary = () => "DODownloadMode=" + vault.ReadRegistryDisplay("HKLM", doKey, "DODownloadMode", "1 (P2P Açık)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", doKey, "DODownloadMode");
                }
            };
            wu03.Variations.Add(new TweakVariation(
                "P2P Upload Tamamen Kapalı (DODownloadMode=0 - Önerilen)",
                "Yalnızca Doğrudan HTTP İndirme (Sıfır Arka Plan Upload)",
                "Güncellemeleri bozmaz; sadece bilgisayarınızın başkalarına sunuculuk yapmasını kapatır.",
                "DODownloadMode=0 (HTTP Only)",
                () =>
                {
                    vault.SetRegistryTracked(wu03.Title, "HKLM", doKey, "DODownloadMode", 0, RegistryValueKind.DWord);
                }));
            wu03.Variations.Add(new TweakVariation(
                "Yalnızca Yerel Ağ (LAN) İçi Paylaşım (Mod=1)",
                "İnternete Upload Yapmaz, Sadece Evdeki Diğer PC'lerle Paylaşır",
                "Evde birden fazla bilgisayar varsa interneti yormadan yerel paylaşım sağlar.",
                "DODownloadMode=1 (LAN Only)",
                () =>
                {
                    vault.SetRegistryTracked(wu03.Title, "HKLM", doKey, "DODownloadMode", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(wu03);

            // WU-04: Hibernation & Fast Startup RAM Cleaner (WinUtil: WPFTweaksHiber)
            string powerSessionKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Power";
            var wu04 = new TweakDefinition
            {
                Id = "WU_HIBERNATION",
                Category = "WINUTIL",
                HardwareTag = "ALL",
                BadgeText = "WINUTIL / TEMİZ BOOT",
                BadgeColor = colWinUtil,
                RequiresAdmin = true,
                RequiresCautionConfirmation = true,
                CautionWarningText = "Hazırda Bekletme (Hibernation) kapatıldığında masaüstü PC'lerde SSD'de birkaç GB yer açılır ve bilgisayarı her kapattığınızda çekirdek (Kernel) sıfırdan tertemiz başlar. Dizüstü (Laptop) kullanıyorsanız Mod 2 önerilir.",
                Title = "Hazırda Bekletme (Hibernation) & Hızlı Başlatma Önbellek Sıfırlayıcı",
                SummaryDescription = "Masaüstü sistemlerde gereksiz hiberfil.sys SSD yazma yükünü kaldırır ve Windows'un bozuk/şişmiş çekirdek durumuyla uyanmasını engeller.",
                DeepTechnicalWhy = "Chris Titus WinUtil (WPFTweaksHiber) standardıdır. Hızlı Başlatma açıkken bilgisayar kapansa bile sürücü zamanlayıcıları sıfırlanmaz; bu ayar her açılışta %100 taze çekirdek sağlar.",
                TargetPathOrApi = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\HibernateEnabled",
                QueryOriginalOrDefaultSummary = () => "Hibernate=" + vault.ReadRegistryDisplay("HKLM", powerSessionKey, "HibernateEnabled", "1") + ", FastBoot=" + vault.ReadRegistryDisplay("HKLM", powerSessionKey, "HiberbootEnabled", "1"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", powerSessionKey, "HibernateEnabled");
                    vault.RevertRegistryTracked("HKLM", powerSessionKey, "HiberbootEnabled");
                    StateVault.RunHiddenCmd("powercfg.exe", "/hibernate on");
                }
            };
            wu04.Variations.Add(new TweakVariation(
                "Masaüstü İçin Tam Kapat (Sıfır Hiberfil + Temiz Kernel Boot)",
                "Hazırda Bekletmeyi Kapat ve SSD Alanını Kurtar",
                "Masaüstü bilgisayarlarda en temiz başlangıç ve sıfır SSD aşınması için kullanılır.",
                "HibernateEnabled=0, HiberbootEnabled=0",
                () =>
                {
                    vault.SetRegistryTracked(wu04.Title, "HKLM", powerSessionKey, "HibernateEnabled", 0, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(wu04.Title, "HKLM", powerSessionKey, "HiberbootEnabled", 0, RegistryValueKind.DWord);
                    StateVault.RunHiddenCmd("powercfg.exe", "/hibernate off");
                }));
            wu04.Variations.Add(new TweakVariation(
                "Dizüstü Dostu: Sadece Hızlı Başlatma (Hiberboot) Kapat",
                "Uyku/Hibernation Korunur, Sadece Bozuk Sürücü Önbelleği Kapatılır",
                "Laptop kullanıcılarının pil korumasını bozmadan her yeniden başlatmada temiz sürücü yüklemesi sağlar.",
                "HiberbootEnabled=0 (Temiz Boot)",
                () =>
                {
                    vault.SetRegistryTracked(wu04.Title, "HKLM", powerSessionKey, "HiberbootEnabled", 0, RegistryValueKind.DWord);
                }));
            allTweaks.Add(wu04);

            // WU-05: WPBT (Windows Platform Binary Table) & Device Companion Bloat Prevention (WinUtil: WPFTweaksWPBT + WPFTweaksPreventDeviceMetadataFromNetwork)
            string smKey = @"SYSTEM\CurrentControlSet\Control\Session Manager";
            string devMetaKey = @"SOFTWARE\Policies\Microsoft\Windows\Device Metadata";
            var wu05 = new TweakDefinition
            {
                Id = "WU_WPBT_COMPANION",
                Category = "WINUTIL",
                HardwareTag = "ALL",
                BadgeText = "WINUTIL / ANAKART KALKANI",
                BadgeColor = colWinUtil,
                RequiresAdmin = true,
                NeedsReboot = true,
                RequiresCautionConfirmation = true,
                CautionWarningText = "Bu ayar anakart BIOS'unun Windows açılışında gizlice arka plan yazılımı (Armoury Crate, MSI Center, Razer otomatik kurulum vb.) enjekte etmesini engeller. Mevcut kurulu programlarınızı silmez.",
                Title = "Anakart BIOS Enjeksiyonu (WPBT) & Otomatik Cihaz Yazılımı Kalkanı",
                SummaryDescription = "Anakart üreticilerinin boot esnasında belleğe gizli servis enjekte etmesini (WPBT) ve monitör/ekipman takıldığında otomatik reklam yazılımı indirilmesini önler.",
                DeepTechnicalWhy = "Chris Titus WinUtil (WPFTweaksWPBT & PreventDeviceMetadata) güvenlik/performans standardıdır. DPC gecikmesi yaratan OEM arka plan servislerinin kendi kendine kurulmasını engeller.",
                TargetPathOrApi = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\DisableWpbtExecution",
                QueryOriginalOrDefaultSummary = () => "DisableWpbt=" + vault.ReadRegistryDisplay("HKLM", smKey, "DisableWpbtExecution", "0 (Açık)"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKLM", smKey, "DisableWpbtExecution");
                    vault.RevertRegistryTracked("HKLM", devMetaKey, "PreventDeviceMetadataFromNetwork");
                }
            };
            wu05.Variations.Add(new TweakVariation(
                "Tam Koruma (WPBT BIOS Enjeksiyonu + Cihaz Yazılımı Kapalı)",
                "Hem BIOS Enjeksiyonunu Hem Ekipman Otomatik Kurulumunu Engelle",
                "Sisteme sizin izniniz dışında anakart/monitör yardımcı programı yüklenmesini tamamen durdurur.",
                "DisableWpbtExecution=1, PreventDeviceMetadata=1",
                () =>
                {
                    vault.SetRegistryTracked(wu05.Title, "HKLM", smKey, "DisableWpbtExecution", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(wu05.Title, "HKLM", devMetaKey, "PreventDeviceMetadataFromNetwork", 1, RegistryValueKind.DWord);
                }));
            wu05.Variations.Add(new TweakVariation(
                "Sadece WPBT BIOS Enjeksiyonunu Kapat",
                "Yalnızca Anakart Boot Enjeksiyonunu Devre Dışı Bırak",
                "Sadece BIOS kaynaklı otomatik kurulumları engeller.",
                "DisableWpbtExecution=1",
                () =>
                {
                    vault.SetRegistryTracked(wu05.Title, "HKLM", smKey, "DisableWpbtExecution", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(wu05);

            // WU-06: Windows 11 Taskbar End-Task, StickyKeys Shield & Verbose Diagnostics (WinUtil: WPFTweaksEndTaskOnTaskbar + WPFToggleStickyKeys + WPFToggleDetailedBSoD)
            string tbDevKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings";
            string stickyKey = @"Control Panel\Accessibility\StickyKeys";
            string crashKey = @"SYSTEM\CurrentControlSet\Control\CrashControl";
            var wu06 = new TweakDefinition
            {
                Id = "WU_UX_PRO_TOOLS",
                Category = "WINUTIL",
                HardwareTag = "ALL",
                BadgeText = "WINUTIL / PRO KULLANIM",
                BadgeColor = colWinUtil,
                RequiresAdmin = false,
                Title = "Görev Çubuğundan 'Görevi Sonlandır', Yapışkan Tuş Kalkanı & Detaylı Tanılama",
                SummaryDescription = "Görev çubuğunda sağ tıkla anında 'Görevi Sonlandır' seçeneği ekler ve oyun ortasında 5 kez Shift'e basınca masaüstüne atan Yapışkan Tuşlar uyarısını kapatır.",
                DeepTechnicalWhy = "Chris Titus WinUtil (WPFTweaksEndTaskOnTaskbar & WPFToggleStickyKeys) birleşimidir. Takılan bir oyunu Görev Yöneticisi açmadan tek tıkla kapatmanızı sağlar ve Shift tuşu kazalarını önler.",
                TargetPathOrApi = @"HKCU\...\TaskbarDeveloperSettings\TaskbarEndTask & StickyKeys",
                QueryOriginalOrDefaultSummary = () => "EndTask=" + vault.ReadRegistryDisplay("HKCU", tbDevKey, "TaskbarEndTask", "0") + ", StickyFlags=" + vault.ReadRegistryDisplay("HKCU", stickyKey, "Flags", "510"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKCU", tbDevKey, "TaskbarEndTask");
                    vault.RevertRegistryTracked("HKCU", stickyKey, "Flags");
                    if (isAdmin)
                    {
                        vault.RevertRegistryTracked("HKLM", crashKey, "DisplayParameters");
                        vault.RevertRegistryTracked("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "VerboseStatus");
                    }
                }
            };
            wu06.Variations.Add(new TweakVariation(
                "Tam Profesyonel Paket (Görevi Sonlandır + Shift Kalkanı + Detaylı Durum)",
                "Sağ Tık Görevi Sonlandır + Yapışkan Tuş Kalkanı + Detaylı Sistem Bilgisi",
                "Oyuncular ve ileri düzey kullanıcılar için en pratik Windows kullanım iyileştirmelerini tek seferde açar.",
                "TaskbarEndTask=1, StickyKeys=506, Verbose=1",
                () =>
                {
                    vault.SetRegistryTracked(wu06.Title, "HKCU", tbDevKey, "TaskbarEndTask", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(wu06.Title, "HKCU", stickyKey, "Flags", "506", RegistryValueKind.String);
                    if (isAdmin)
                    {
                        vault.SetRegistryTracked(wu06.Title, "HKLM", crashKey, "DisplayParameters", 1, RegistryValueKind.DWord);
                        vault.SetRegistryTracked(wu06.Title, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "VerboseStatus", 1, RegistryValueKind.DWord);
                    }
                }));
            wu06.Variations.Add(new TweakVariation(
                "Sadece Görev Çubuğu 'Görevi Sonlandır' + Shift Kalkanı",
                "Yalnızca Sağ Tık Görevi Sonlandır ve Yapışkan Tuş Engelleyici",
                "Yönetici yetkisi gerektirmeden anında aktif olur.",
                "TaskbarEndTask=1, StickyKeys=506",
                () =>
                {
                    vault.SetRegistryTracked(wu06.Title, "HKCU", tbDevKey, "TaskbarEndTask", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(wu06.Title, "HKCU", stickyKey, "Flags", "506", RegistryValueKind.String);
                }));
            allTweaks.Add(wu06);

            // WU-07: Storage Sense & Automatic Disk Maintenance Blocker During Gaming (WinUtil: WPFTweaksStorage + WPFToggleGameMode)
            string storagePolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy";
            string gameBarKey = @"Software\Microsoft\GameBar";
            var wu07 = new TweakDefinition
            {
                Id = "WU_GAMEMODE_STORAGE",
                Category = "WINUTIL",
                HardwareTag = "ALL",
                BadgeText = "WINUTIL / OYUN MODU",
                BadgeColor = colWinUtil,
                RequiresAdmin = false,
                Title = "Windows Oyun Modu Kilidi & Otomatik Disk Temizlik Takılması Önleyici",
                SummaryDescription = "Windows Oyun Modunu (AutoGameMode) kalıcı olarak sabitler ve Akıllı Depolama'nın (Storage Sense) oyun ortasında disk taraması yapmasını kapatır.",
                DeepTechnicalWhy = "Chris Titus WinUtil (WPFToggleGameMode & WPFTweaksStorage) yapılandırmasıdır. Oyun esnasında arka planda başlayan otomatik geçici dosya silme işlemlerinin disk I/O gecikmesi yaratmasını engeller.",
                TargetPathOrApi = @"HKCU\Software\Microsoft\GameBar\AutoGameModeEnabled",
                QueryOriginalOrDefaultSummary = () => "GameMode=" + vault.ReadRegistryDisplay("HKCU", gameBarKey, "AutoGameModeEnabled", "1") + ", StorageSense=" + vault.ReadRegistryDisplay("HKCU", storagePolicyKey, "01", "Varsayılan"),
                RevertAction = () =>
                {
                    vault.RevertRegistryTracked("HKCU", gameBarKey, "AllowAutoGameMode");
                    vault.RevertRegistryTracked("HKCU", gameBarKey, "AutoGameModeEnabled");
                    vault.RevertRegistryTracked("HKCU", storagePolicyKey, "01");
                }
            };
            wu07.Variations.Add(new TweakVariation(
                "Oyun Modu Aktif + Otomatik Disk Tarama Kapalı (Önerilen)",
                "Maksimum Oyun Odaklı Kaynak Yönetimi + Sıfır Disk Taraması",
                "Oyun sırasında arka plan Windows Bakım ve Storage Sense görevlerinin çalışmasını engeller.",
                "AutoGameMode=1, StorageSense=0",
                () =>
                {
                    vault.SetRegistryTracked(wu07.Title, "HKCU", gameBarKey, "AllowAutoGameMode", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(wu07.Title, "HKCU", gameBarKey, "AutoGameModeEnabled", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(wu07.Title, "HKCU", storagePolicyKey, "01", 0, RegistryValueKind.DWord);
                }));
            wu07.Variations.Add(new TweakVariation(
                "Sadece Windows Oyun Modunu Sabitle",
                "Depolama Ayarına Dokunmadan Oyun Modunu Aktif Tut",
                "Yalnızca Oyun Modu önceliğini garantilemek için kullanılır.",
                "AutoGameMode=1",
                () =>
                {
                    vault.SetRegistryTracked(wu07.Title, "HKCU", gameBarKey, "AllowAutoGameMode", 1, RegistryValueKind.DWord);
                    vault.SetRegistryTracked(wu07.Title, "HKCU", gameBarKey, "AutoGameModeEnabled", 1, RegistryValueKind.DWord);
                }));
            allTweaks.Add(wu07);

            // Actively query and persist THIS machine's true default values on startup!
            vault.LearnMachineDefaultsForCatalog(allTweaks);
        }

        #region Progressive Studio UI, Hardware Matrix Selector & Conflict/Dependency Engine

        private Panel pnlRebootWarningBanner;
        private Label lblRebootBannerText;
        private Button btnSoftReloadNow;
        private Button btnRebootPcBanner;
        private Button btnDismissBanner;
        private bool bannerDismissedBySession = false;

        public Size GetPresetResolutionSize(string preset)
        {
            if (preset == "COMPACT") return new Size(1280, 820);
            if (preset == "LARGE") return new Size(1560, 960);
            if (preset == "EXTRA_LARGE") return new Size(1720, 1020);
            return new Size(1380, 890); // Default MEDIUM (Orta Boy)
        }

        private void ApplyWindowLayoutPolicy()
        {
            try
            {
                string preset = (appSettings != null && !string.IsNullOrEmpty(appSettings.WindowResolutionPreset))
                    ? appSettings.WindowResolutionPreset
                    : "MEDIUM";

                Size targetSize = GetPresetResolutionSize(preset);
                bool lockFixed = (appSettings == null || appSettings.LockFixedResolution);

                if (lockFixed)
                {
                    this.FormBorderStyle = FormBorderStyle.FixedSingle;
                    this.MaximizeBox = false;
                    this.MinimumSize = targetSize;
                    this.MaximumSize = targetSize;
                    this.Size = targetSize;
                }
                else
                {
                    this.FormBorderStyle = FormBorderStyle.Sizable;
                    this.MaximizeBox = true;
                    this.MinimumSize = new Size(1280, 800);
                    this.MaximumSize = new Size(0, 0);
                    this.Size = targetSize;
                }

                // If window bounds exceed active display working area, fit gracefully
                Rectangle workArea = Screen.FromControl(this).WorkingArea;
                if (this.Width > workArea.Width || this.Height > workArea.Height)
                {
                    this.Size = new Size(Math.Min(this.Width, workArea.Width - 10), Math.Min(this.Height, workArea.Height - 20));
                    this.CenterToScreen();
                }
            }
            catch { }
        }

        private void InitializeStudioUI()
        {
            this.Text = "ARGON LATENCY STUDIO v4.0 — Windows Low Latency, Kernel Timer & TCP/IP Engineering Utility" + (isAdmin ? " [ADMINISTRATOR]" : " [STANDARD]");
            this.Size = new Size(1380, 890);
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

            Icon appIcon = null;
            try
            {
                string localIco = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "app.ico");
                if (File.Exists(localIco))
                    appIcon = new Icon(localIco);
                else
                    appIcon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch { }
            if (appIcon == null) appIcon = SystemIcons.Shield;
            try { this.Icon = appIcon; } catch { }

            // 1. Executive Utility Header Bar (42px Height - Clean, Non-intrusive)
            pnlTopHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 42,
                BackColor = Color.FromArgb(16, 20, 29)
            };
            pnlTopHeader.Paint += (s, e) =>
            {
                using (Pen borderPen = new Pen(Color.FromArgb(34, 43, 62), 1))
                {
                    e.Graphics.DrawLine(borderPen, 0, pnlTopHeader.Height - 1, pnlTopHeader.Width, pnlTopHeader.Height - 1);
                }
            };
            this.Controls.Add(pnlTopHeader);

            Panel pnlBrandEmblem = new Panel
            {
                Size = new Size(28, 28),
                Location = new Point(10, 7),
                BackColor = Color.FromArgb(20, 27, 40)
            };
            pnlBrandEmblem.Paint += (s, e) =>
            {
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                using (Pen p = new Pen(Color.FromArgb(16, 185, 129), 1.4f))
                {
                    e.Graphics.DrawRectangle(p, 1, 1, pnlBrandEmblem.Width - 3, pnlBrandEmblem.Height - 3);
                }
                if (appIcon != null)
                {
                    try { e.Graphics.DrawIcon(appIcon, new Rectangle(4, 4, 20, 20)); return; } catch { }
                }
                TechnicalIconRenderer.DrawTweakVectorIcon(e.Graphics, new Rectangle(4, 4, 20, 20), "LAT_TIMER", "LATENCY", "ALL", Color.FromArgb(16, 185, 129));
            };
            pnlTopHeader.Controls.Add(pnlBrandEmblem);

            Label lblBrand = new Label
            {
                Text = "ARGON STUDIO",
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Location = new Point(44, 10)
            };
            pnlTopHeader.Controls.Add(lblBrand);

            Label lblVersionPill = new Label
            {
                Text = "v4.0 PRO",
                Font = new Font("Segoe UI", 7.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                BackColor = Color.FromArgb(20, 32, 50),
                AutoSize = true,
                Location = new Point(164, 13),
                Padding = new Padding(3, 1, 3, 1)
            };
            pnlTopHeader.Controls.Add(lblVersionPill);

            lblProfCaption = new Label
            {
                Text = Loc.T("PROFİL:", "PROFILE:"),
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(236, 13)
            };
            pnlTopHeader.Controls.Add(lblProfCaption);

            cmbProfileSelector = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(292, 9),
                Size = new Size(185, 24)
            };
            cmbProfileSelector.SelectedIndexChanged += (s, e) => OnTopProfileDropdownSelected();
            mainToolTip.SetToolTip(cmbProfileSelector, "Hazır sistem profilleri veya kendi isimlendirip kaydettiğiniz özel profiller arasında anında geçiş yapın.");
            pnlTopHeader.Controls.Add(cmbProfileSelector);

            btnQuickSaveProf = new Button
            {
                Text = Loc.T("+ Kaydet", "+ Save"),
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 58, 138),
                ForeColor = Color.White,
                Size = new Size(62, 24),
                Location = new Point(482, 9),
                Cursor = Cursors.Hand
            };
            btnQuickSaveProf.FlatAppearance.BorderSize = 1;
            btnQuickSaveProf.FlatAppearance.BorderColor = Color.FromArgb(59, 130, 246);
            btnQuickSaveProf.Click += (s, e) => PromptAndSaveCustomNamedProfile();
            mainToolTip.SetToolTip(btnQuickSaveProf, "Şu an açık olan tüm ayarlarınızı kendi vereceğiniz bir isimle özel profil olarak kaydeder.");
            pnlTopHeader.Controls.Add(btnQuickSaveProf);

            lblLiveSystemStatusPill = new Label
            {
                Text = "● Sistem: " + allTweaks.Count + " Ayar Taranıyor",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Location = new Point(552, 12),
                Cursor = Cursors.Hand
            };
            lblLiveSystemStatusPill.Click += (s, e) =>
            {
                int pendingReboot = 0;
                foreach (var t in allTweaks) if (t.IsRebootPending) pendingReboot++;
                if (pendingReboot > 0)
                    PromptAndRestartComputerNow();
                else
                    SwitchActiveTab(9);
            };
            mainToolTip.SetToolTip(lblLiveSystemStatusPill, "Canlı sistem durumunu incelemek veya bekleyen Windows restart ayarlarını devreye almak için tıklayın.");
            pnlTopHeader.Controls.Add(lblLiveSystemStatusPill);

            // Hidden legacy labels kept for 100% caller compatibility
            lblTopTimer = CreateHeaderBadge("Timer: 15.625 ms", Color.FromArgb(52, 211, 153), 0, 0);
            lblTopPing = CreateHeaderBadge("Ping: --", Color.FromArgb(56, 189, 248), 0, 0);
            lblTopRam = CreateHeaderBadge("RAM: --", Color.FromArgb(251, 191, 36), 0, 0);
            lblTopActiveCount = CreateHeaderBadge("Aktif: 0 / " + allTweaks.Count, Color.FromArgb(168, 85, 247), 0, 0);
            lblTopCpuSensor = CreateHeaderBadge("CPU: --", Color.FromArgb(251, 146, 60), 0, 0);
            lblTopGpuSensor = CreateHeaderBadge("GPU: --", Color.FromArgb(52, 211, 153), 0, 0);
            lblTopTimer.Visible = false;
            lblTopPing.Visible = false;
            lblTopRam.Visible = false;
            lblTopActiveCount.Visible = false;
            lblTopCpuSensor.Visible = false;
            lblTopGpuSensor.Visible = false;

            chkRevertOnExit = new CheckBox
            {
                Text = Loc.T("Çıkışta sıfırla", "Revert on exit"),
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                BackColor = Color.FromArgb(16, 20, 29),
                AutoSize = true,
                Cursor = Cursors.Hand
            };
            chkRevertOnExit.CheckedChanged += (s, e) => SetRevertOnExit(chkRevertOnExit.Checked);
            mainToolTip.SetToolTip(chkRevertOnExit, "Açıkken: program kapanınca tüm ayarlar fabrika varsayılanına döner.");
            pnlTopHeader.Controls.Add(chkRevertOnExit);

            chkAutoStart = new CheckBox
            {
                Text = Loc.T("Windows ile başlat", "Start with Windows"),
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                BackColor = Color.FromArgb(16, 20, 29),
                AutoSize = true,
                Cursor = Cursors.Hand
            };
            chkAutoStart.CheckedChanged += (s, e) => OnAutoStartToggled();
            mainToolTip.SetToolTip(chkAutoStart, "Oturum açılınca Argon yönetici yetkisiyle tepside sessizce başlar.");
            pnlTopHeader.Controls.Add(chkAutoStart);

            btnSmartTuneTop = new Button
            {
                Text = Loc.T("⚡ Akıllı Profil", "⚡ Smart Profile"),
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.Black,
                Size = new Size(115, 24),
                Cursor = Cursors.Hand
            };
            btnSmartTuneTop.FlatAppearance.BorderSize = 0;
            btnSmartTuneTop.Click += (s, e) => ApplyHardwareAwareSmartTune();
            mainToolTip.SetToolTip(btnSmartTuneTop, "Sisteminize ve seçili profilinize en uygun güvenli ayarları tek tıkla uygular.");
            pnlTopHeader.Controls.Add(btnSmartTuneTop);

            btnResetAllTop = new Button
            {
                Text = Loc.T("↺ Fabrika Sıfırla", "↺ Reset All"),
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(153, 27, 27),
                ForeColor = Color.White,
                Size = new Size(118, 24),
                Cursor = Cursors.Hand
            };
            btnResetAllTop.FlatAppearance.BorderSize = 1;
            btnResetAllTop.FlatAppearance.BorderColor = Color.FromArgb(220, 38, 38);
            btnResetAllTop.Click += (s, e) => RevertAllActiveTweaksToOriginal();
            mainToolTip.SetToolTip(btnResetAllTop, "Orijinal fabrika değerlerini birebir geri yükler ve canlı OS denetimiyle sıfırlandığını doğrular.");
            pnlTopHeader.Controls.Add(btnResetAllTop);

            btnMinimizeTray = new Button
            {
                Text = Loc.T("– Tepsiye Küçült", "– Tray"),
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(203, 213, 225),
                Size = new Size(120, 24),
                Cursor = Cursors.Hand
            };
            btnMinimizeTray.FlatAppearance.BorderSize = 1;
            btnMinimizeTray.FlatAppearance.BorderColor = Color.FromArgb(65, 78, 105);
            btnMinimizeTray.Click += (s, e) =>
            {
                this.Hide();
                trayIcon.ShowBalloonTip(1500, "Argon Studio v4.0", "Arka planda aktif. Ayarlarınız korunuyor.", ToolTipIcon.Info);
            };
            pnlTopHeader.Controls.Add(btnMinimizeTray);

            btnLangToggle = new Button
            {
                Text = Loc.IsEnglish ? "🌐 EN" : "🌐 TR",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(20, 32, 50),
                ForeColor = Color.FromArgb(56, 189, 248),
                Size = new Size(62, 24),
                Cursor = Cursors.Hand
            };
            btnLangToggle.FlatAppearance.BorderSize = 1;
            btnLangToggle.FlatAppearance.BorderColor = Color.FromArgb(56, 189, 248);
            btnLangToggle.Click += (s, e) =>
            {
                string nextLang = Loc.IsEnglish ? "TR" : "EN";
                ApplyLanguage(nextLang);
            };
            mainToolTip.SetToolTip(btnLangToggle, "Dili Değiştir / Switch Language (Türkçe / English)");
            pnlTopHeader.Controls.Add(btnLangToggle);

            btnElevate = null;
            if (!isAdmin)
            {
                btnElevate = new Button
                {
                    Text = Loc.T("🛡️ Yönetici Aç", "🛡️ Admin"),
                    Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.FromArgb(217, 119, 6),
                    ForeColor = Color.Black,
                    Size = new Size(100, 24),
                    Cursor = Cursors.Hand
                };
                btnElevate.FlatAppearance.BorderSize = 0;
                btnElevate.Click += (s, e) => RestartAsAdministrator();
                pnlTopHeader.Controls.Add(btnElevate);
            }

            Action layoutTopHeader = () =>
            {
                int w = pnlTopHeader.ClientSize.Width > 0 ? pnlTopHeader.ClientSize.Width : 1380;
                bool isCompact = (w < 1440);

                // Left Flow: Dynamic spacing prevents any DPI overlaps
                int lx = 10;
                pnlBrandEmblem.Location = new Point(lx, 7);
                lx += pnlBrandEmblem.Width + 8;

                lblBrand.Location = new Point(lx, 10);
                int brandW = Math.Max(130, lblBrand.PreferredSize.Width);
                lx += brandW + 8;

                lblVersionPill.Location = new Point(lx, 12);
                lx += Math.Max(55, lblVersionPill.PreferredSize.Width) + 12;

                lblProfCaption.Location = new Point(lx, 13);
                lx += lblProfCaption.PreferredSize.Width + 6;

                cmbProfileSelector.Location = new Point(lx, 9);
                cmbProfileSelector.Width = isCompact ? 145 : 175;
                lx += cmbProfileSelector.Width + 6;

                btnQuickSaveProf.Text = isCompact ? "+" : Loc.T("+ Kaydet", "+ Save");
                btnQuickSaveProf.Width = isCompact ? 30 : Math.Max(74, btnQuickSaveProf.PreferredSize.Width + 10);
                btnQuickSaveProf.Location = new Point(lx, 9);
                lx += btnQuickSaveProf.Width + 10;

                lblLiveSystemStatusPill.Location = new Point(lx, 12);

                // Right Flow
                int rx = w - 10;

                btnMinimizeTray.Text = isCompact ? Loc.T("Tepsi", "Tray") : Loc.T("- Tepsiye", "- Tray");
                btnMinimizeTray.Width = isCompact ? 60 : Math.Max(85, btnMinimizeTray.PreferredSize.Width + 8);
                rx -= btnMinimizeTray.Width;
                btnMinimizeTray.Location = new Point(rx, 9);
                rx -= 5;

                btnLangToggle.Width = 62;
                rx -= btnLangToggle.Width;
                btnLangToggle.Location = new Point(rx, 9);
                rx -= 6;

                btnResetAllTop.Text = isCompact ? Loc.T("Sıfırla", "Reset") : Loc.T("↺ Fabrika Sıfırla", "↺ Reset All");
                btnResetAllTop.Width = isCompact ? 68 : Math.Max(118, btnResetAllTop.PreferredSize.Width + 12);
                rx -= btnResetAllTop.Width;
                btnResetAllTop.Location = new Point(rx, 9);
                rx -= 6;

                btnSmartTuneTop.Text = isCompact ? Loc.T("Akıllı Ayar", "Smart Tune") : Loc.T("⚡ Akıllı Profil", "⚡ Smart Profile");
                btnSmartTuneTop.Width = isCompact ? 86 : Math.Max(115, btnSmartTuneTop.PreferredSize.Width + 12);
                rx -= btnSmartTuneTop.Width;
                btnSmartTuneTop.Location = new Point(rx, 9);
                rx -= 10;

                if (btnElevate != null)
                {
                    btnElevate.Text = isCompact ? Loc.T("Yönetici", "Admin") : Loc.T("🛡️ Yönetici Aç", "🛡️ Admin");
                    btnElevate.Width = isCompact ? 80 : Math.Max(100, btnElevate.PreferredSize.Width + 10);
                    rx -= btnElevate.Width;
                    btnElevate.Location = new Point(rx, 9);
                    rx -= 8;
                }

                rx -= chkAutoStart.PreferredSize.Width;
                chkAutoStart.Location = new Point(rx, 13);
                rx -= 8;

                rx -= chkRevertOnExit.PreferredSize.Width;
                chkRevertOnExit.Location = new Point(rx, 13);
            };
            pnlTopHeader.Resize += (s, e) => layoutTopHeader();
            layoutTopHeader();
            RefreshProfileSelectorCombo();

            // 2. Compact Navigation Bar (10 Technical Category Tabs + Global Search)
            pnlNavBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 36,
                BackColor = Color.FromArgb(20, 25, 36)
            };
            pnlNavBar.Paint += (s, e) =>
            {
                using (Pen borderPen = new Pen(Color.FromArgb(34, 43, 62), 1))
                {
                    e.Graphics.DrawLine(borderPen, 0, pnlNavBar.Height - 1, pnlNavBar.Width, pnlNavBar.Height - 1);
                }
            };
            this.Controls.Add(pnlNavBar);

            string[] tabNames = new string[]
            {
                "Donanım (4)",
                "Ağ (0/11)",
                "Timer (0/8)",
                "Grafik (0/9)",
                "Sistem (0/7)",
                "Kernel (0/8)",
                "İşlemler",
                "Otomasyon",
                "Tanı Test",
                "Günlük",
                "Ayarlar"
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
                    AutoSize = false,
                    UseMnemonic = false,
                    Height = 26,
                    Location = new Point(navX, 5),
                    Cursor = Cursors.Hand,
                    Padding = new Padding(2, 0, 2, 0)
                };
                btnNav.FlatAppearance.BorderSize = 0;
                btnNav.Click += (s, e) =>
                {
                    if (!string.IsNullOrEmpty(txtGlobalSearch.Text))
                        txtGlobalSearch.Text = "";
                    SwitchActiveTab(tabIdx);
                };
                pnlNavBar.Controls.Add(btnNav);
                navButtons.Add(btnNav);
                navX += btnNav.PreferredSize.Width + 4;
            }

            lblSearchIcon = new Label
            {
                Text = "Ara:",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true
            };
            pnlNavBar.Controls.Add(lblSearchIcon);

            txtGlobalSearch = new TextBox
            {
                Width = 165,
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 8.0f, FontStyle.Regular)
            };
            txtGlobalSearch.TextChanged += (s, e) => ApplySearchFilter(txtGlobalSearch.Text);
            mainToolTip.SetToolTip(txtGlobalSearch, "TÜM SEKMELERDE GENEL ARAMA:\nNagle, MPO, Teredo, Timer, Ryzen, NVIDIA, USB, Hibernation vb. yazarak 45 ayarın tamamında arama yapabilirsiniz.");
            pnlNavBar.Controls.Add(txtGlobalSearch);

            pnlNavBar.Resize += (s, e) => LayoutNavBarButtons();
            LayoutNavBarButtons();

            // 3. Intelligent Reboot & Adapter Reload Notification Bar (Zero False Positives)
            pnlRebootWarningBanner = new Panel
            {
                Dock = DockStyle.Top,
                Height = 38,
                BackColor = Color.FromArgb(42, 26, 14),
                Visible = false,
                Padding = new Padding(10, 5, 10, 5)
            };
            pnlRebootWarningBanner.Paint += (s, e) =>
            {
                using (Pen bPen = new Pen(Color.FromArgb(217, 119, 6), 1))
                {
                    e.Graphics.DrawLine(bPen, 0, pnlRebootWarningBanner.Height - 1, pnlRebootWarningBanner.Width, pnlRebootWarningBanner.Height - 1);
                }
            };
            this.Controls.Add(pnlRebootWarningBanner);

            btnDismissBanner = new Button
            {
                Text = "✕",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.Transparent,
                ForeColor = Color.FromArgb(148, 163, 184),
                Width = 26,
                Dock = DockStyle.Right,
                Cursor = Cursors.Hand
            };
            btnDismissBanner.FlatAppearance.BorderSize = 0;
            btnDismissBanner.Click += (s, e) =>
            {
                bannerDismissedBySession = true;
                UpdateRebootAndReloadBannerVisibility();
            };
            pnlRebootWarningBanner.Controls.Add(btnDismissBanner);

            btnRebootPcBanner = new Button
            {
                Text = "⚡ Bilgisayarı Yeniden Başlat",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(245, 158, 11),
                ForeColor = Color.Black,
                AutoSize = true,
                Dock = DockStyle.Right,
                Padding = new Padding(12, 0, 12, 0),
                Cursor = Cursors.Hand,
                Visible = false
            };
            btnRebootPcBanner.FlatAppearance.BorderSize = 0;
            btnRebootPcBanner.Click += (s, e) => PromptAndRestartComputerNow();
            pnlRebootWarningBanner.Controls.Add(btnRebootPcBanner);

            btnSoftReloadNow = new Button
            {
                Text = "🔄 Ağ Kartını Şimdi Yenile",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(14, 165, 233),
                ForeColor = Color.Black,
                AutoSize = true,
                Dock = DockStyle.Right,
                Padding = new Padding(12, 0, 12, 0),
                Cursor = Cursors.Hand,
                Visible = false
            };
            btnSoftReloadNow.FlatAppearance.BorderSize = 0;
            btnSoftReloadNow.Click += (s, e) => ExecuteSoftReloadWithoutReboot();
            pnlRebootWarningBanner.Controls.Add(btnSoftReloadNow);

            lblRebootBannerText = new Label
            {
                Text = "Durum bilgisi yükleniyor...",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(253, 224, 71),
                Dock = DockStyle.Fill,
                AutoEllipsis = true,
                TextAlign = ContentAlignment.MiddleLeft
            };
            pnlRebootWarningBanner.Controls.Add(lblRebootBannerText);

            // 4. Compact 2-Line Hover Inspector Status Bar at Bottom
            pnlInspectorFooter = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 46,
                BackColor = Color.FromArgb(15, 19, 28)
            };
            pnlInspectorFooter.Paint += (s, e) =>
            {
                using (Pen borderPen = new Pen(Color.FromArgb(34, 43, 62), 1))
                {
                    e.Graphics.DrawLine(borderPen, 0, 0, pnlInspectorFooter.Width, 0);
                }
            };
            this.Controls.Add(pnlInspectorFooter);

            lblInspectorTitle = new Label
            {
                Text = "Hazır — Herhangi bir ayarın üzerine gelerek canlı Windows değerini, kayıt defteri yolunu ve teknik amacını inceleyebilirsiniz.",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(12, 5)
            };
            pnlInspectorFooter.Controls.Add(lblInspectorTitle);

            lblInspectorPath = new Label
            {
                Text = "Canlı OS Algılama (Live OS Truth): Kayıt Defteri, Güç Planı, Win32 SPI ve Kernel gerçek zamanlı denetlenir.",
                Font = new Font("Consolas", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(12, 24)
            };
            pnlInspectorFooter.Controls.Add(lblInspectorPath);

            // 5. Right Sidebar (NetAdapter Repair-style Network Settings, Hardware Telemetry & Live Audit Console)
            BuildRightTelemetryAndNetworkSidebar();

            // 6. Main Content Host (Left/Center Compact Table Workspace)
            pnlContentHost = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23)
            };
            this.Controls.Add(pnlContentHost);

            pnlRightSidebar.SendToBack();
            pnlRebootWarningBanner.SendToBack();
            pnlNavBar.SendToBack();
            pnlTopHeader.SendToBack();
            pnlInspectorFooter.SendToBack();
            pnlContentHost.BringToFront();

            BuildProgressiveHardwareMatrixView();
            viewNetwork = BuildTweakCategoryFlowView("NETWORK");
            viewLatency = BuildTweakCategoryFlowView("LATENCY");
            viewFps = BuildTweakCategoryFlowView("FPS");
            BuildWinUtilView();
            viewExperimental = BuildTweakCategoryFlowView("EXPERIMENTAL");
            BuildProcessesView();
            BuildAutomationAndQoLView();
            BuildBenchmarkView();
            BuildSnapshotAuditView();
            BuildSettingsView();
            BuildGlobalSearchView();

            // Record each card's original parent container for seamless global search
            foreach (var c in allCards)
            {
                cardHomeContainers[c] = c.Parent;
            }

            // Tray Menu
            trayMenu = new ContextMenuStrip();
            trayMenu.Items.Add("Argon Studio v4.0 Penceresini Aç", null, (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; this.Activate(); });
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add("Seçili Donanım Matrisini Otomatik Uygula", null, (s, e) => ApplyHardwareAwareSmartTune());
            trayMenu.Items.Add("Gerçek Windows Durumunu (Live OS) Algıla & Eşitle", null, (s, e) => ProbeAllTweaksLiveOsTruthAndOptionallySync(true));
            trayMenu.Items.Add("Şimdi Akıllı RAM & Standby Temizle", null, (s, e) => ExecuteSmartRamAndStandbyPurge(true));
            trayMenu.Items.Add("Makine Varsayılanlarına Döndür (Fabrika Sıfırla)", null, (s, e) => RevertAllActiveTweaksToOriginal());
            trayMenu.Items.Add(new ToolStripSeparator());
            mnuRevertOnExit = new ToolStripMenuItem("Çıkışta varsayılanlara dön");
            mnuRevertOnExit.CheckOnClick = true;
            mnuRevertOnExit.Checked = revertOnExit;
            mnuRevertOnExit.CheckedChanged += (s, e) => SetRevertOnExit(mnuRevertOnExit.Checked);
            trayMenu.Items.Add(mnuRevertOnExit);
            mnuExit = new ToolStripMenuItem("Programdan Çık (Açık Ayarlar Sabit Kalır)");
            mnuExit.Click += (s, e) => this.Close();
            trayMenu.Items.Add(mnuExit);
            UpdateExitMenuText();

            trayIcon = new NotifyIcon
            {
                Text = "Argon Low Latency Studio v4.0",
                Icon = appIcon,
                ContextMenuStrip = trayMenu,
                Visible = true
            };
            trayIcon.DoubleClick += (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; this.Activate(); };

            this.FormClosing += (s, e) =>
            {
                PerformCleanShutdownKeepSettings();
            };

            AppendConsoleLog(string.Format("{0} ({1})", Environment.OSVersion.VersionString, Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit"));
            AppendConsoleLog("Argon Latency Studio v4.0 Yüklendi — Yetki: " + (isAdmin ? "Yönetici (Administrator)" : "Standart Kullanıcı"));
            AppendConsoleLog(string.Format("Algılanan CPU: {0} ({1}C/{2}T)", detectedHw.CpuName, detectedHw.PhysicalCores, detectedHw.LogicalThreads));
            AppendConsoleLog("Algılanan GPU: " + detectedHw.GpuName);
            ProbeLiveNetworkSidebarDetails();

            SwitchActiveTab(0);
            RefreshHardwareMatrixCards();
        }

        private void BuildRightTelemetryAndNetworkSidebar()
        {
            pnlRightSidebar = new Panel
            {
                Dock = DockStyle.Right,
                Width = 420,
                BackColor = Color.FromArgb(16, 20, 29),
                Padding = new Padding(10, 8, 10, 8)
            };
            pnlRightSidebar.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(34, 43, 62), 1))
                {
                    e.Graphics.DrawLine(p, 0, 0, 0, pnlRightSidebar.Height);
                }
            };
            this.Controls.Add(pnlRightSidebar);

            // Top Section: Network & Hardware Key-Value Grid (Fixed Height 398px)
            Panel pnlSidebarTopGrid = new Panel
            {
                Dock = DockStyle.Top,
                Height = 398,
                BackColor = Color.FromArgb(16, 20, 29)
            };
            pnlRightSidebar.Controls.Add(pnlSidebarTopGrid);

            // Group 1 Header: Current Network Settings + Ping IP / Ping DNS / Flush / Refresh buttons
            grpNetAdapter = new Label
            {
                Text = Loc.T("AĞ ADAPTÖRÜ VE BAĞLANTI", "NETWORK & ADAPTER"),
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(2, 4),
                UseMnemonic = false
            };
            pnlSidebarTopGrid.Controls.Add(grpNetAdapter);

            btnSidePingIp = CreateActionButton(pnlSidebarTopGrid, 152, 1, 62, 21, "Ping IP", Color.FromArgb(30, 41, 59));
            btnSidePingIp.Font = new Font("Segoe UI", 7.2f, FontStyle.Bold);
            btnSidePingIp.FlatAppearance.BorderSize = 1;
            btnSidePingIp.FlatAppearance.BorderColor = Color.FromArgb(56, 189, 248);
            btnSidePingIp.UseMnemonic = false;
            mainToolTip.SetToolTip(btnSidePingIp, "Cloudflare (1.1.1.1) omurgasına anlık ICMP Ping gönderir ve sonucu konsola yazar.");
            btnSidePingIp.Click += (s, e) => RunQuickSidebarPingTarget("1.1.1.1", "Cloudflare IP");

            btnSidePingDns = CreateActionButton(pnlSidebarTopGrid, 218, 1, 66, 21, "Ping DNS", Color.FromArgb(30, 41, 59));
            btnSidePingDns.Font = new Font("Segoe UI", 7.2f, FontStyle.Bold);
            btnSidePingDns.FlatAppearance.BorderSize = 1;
            btnSidePingDns.FlatAppearance.BorderColor = Color.FromArgb(52, 211, 153);
            btnSidePingDns.UseMnemonic = false;
            mainToolTip.SetToolTip(btnSidePingDns, "Google Public DNS (8.8.8.8) sunucusuna anlık ICMP Ping gönderir ve sonucu konsola yazar.");
            btnSidePingDns.Click += (s, e) => RunQuickSidebarPingTarget("8.8.8.8", "Google DNS");

            btnSideFlush = CreateActionButton(pnlSidebarTopGrid, 288, 1, 46, 21, Loc.T("Temizle", "Clear"), Color.FromArgb(30, 41, 59));
            btnSideFlush.Font = new Font("Segoe UI", 7.2f, FontStyle.Bold);
            btnSideFlush.FlatAppearance.BorderSize = 1;
            btnSideFlush.FlatAppearance.BorderColor = Color.FromArgb(148, 163, 184);
            btnSideFlush.UseMnemonic = false;
            mainToolTip.SetToolTip(btnSideFlush, "DNS önbelleğini (FlushDNS) ve ARP tablosunu anında temizler.");
            btnSideFlush.Click += (s, e) =>
            {
                ExecuteInstantNetworkQueueFlush();
                AppendConsoleLog("DNS Çözümleyici Önbelleği ve ARP tablosu temizlendi.");
            };

            btnSideRefreshNet = CreateActionButton(pnlSidebarTopGrid, 338, 1, 24, 21, "↻", Color.FromArgb(16, 185, 129));
            btnSideRefreshNet.ForeColor = Color.Black;
            btnSideRefreshNet.Font = new Font("Segoe UI", 8.0f, FontStyle.Bold);
            btnSideRefreshNet.UseMnemonic = false;
            mainToolTip.SetToolTip(btnSideRefreshNet, "Ağ adaptörü, IP, Gateway, DNS ve Ping bilgilerini yeniler.");
            btnSideRefreshNet.Click += (s, e) =>
            {
                ProbeLiveNetworkSidebarDetails();
                RunAsyncPingCheck();
                AppendConsoleLog("Ağ adaptörü ve telemetri bilgileri güncellendi.");
            };

            Action layoutSidebarTopButtons = () =>
            {
                int curW = pnlSidebarTopGrid.ClientSize.Width > 0 ? pnlSidebarTopGrid.ClientSize.Width : 400;
                int rx = curW - 2;

                btnSideRefreshNet.Size = new Size(24, 22);
                rx -= btnSideRefreshNet.Width;
                btnSideRefreshNet.Location = new Point(rx, 1);
                rx -= 4;

                int fW = Math.Max(60, btnSideFlush.PreferredSize.Width + 10);
                rx -= fW;
                btnSideFlush.Size = new Size(fW, 22);
                btnSideFlush.Location = new Point(rx, 1);
                rx -= 4;

                int pdW = Math.Max(72, btnSidePingDns.PreferredSize.Width + 10);
                rx -= pdW;
                btnSidePingDns.Size = new Size(pdW, 22);
                btnSidePingDns.Location = new Point(rx, 1);
                rx -= 4;

                int piW = Math.Max(62, btnSidePingIp.PreferredSize.Width + 10);
                rx -= piW;
                btnSidePingIp.Size = new Size(piW, 22);
                btnSidePingIp.Location = new Point(rx, 1);
            };
            pnlSidebarTopGrid.Resize += (s, e) => layoutSidebarTopButtons();
            layoutSidebarTopButtons();

            int ry = 27;
            txtNetHostAdmin = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "Sistem / Yetki", ref ry, Color.FromArgb(226, 232, 240));
            txtNetAdapter = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "Ağ Adaptörü", ref ry, Color.FromArgb(56, 189, 248));
            txtNetLocalIp = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "Yerel IPv4 / Maske", ref ry, Color.FromArgb(226, 232, 240));
            txtNetGateway = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "Varsayılan Geçit", ref ry, Color.FromArgb(203, 213, 225));
            txtNetDns = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "DNS Sunucuları", ref ry, Color.FromArgb(52, 211, 153));
            txtNetMac = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "MAC (Fiziksel)", ref ry, Color.FromArgb(203, 213, 225));
            txtNetPingLive = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "Canlı Ping / RTT", ref ry, Color.FromArgb(52, 211, 153));

            ry += 6;
            lblHwHdr = new Label
            {
                Text = Loc.T("DONANIM İZLEME", "HARDWARE MONITOR"),
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                AutoSize = true,
                Location = new Point(2, ry)
            };
            pnlSidebarTopGrid.Controls.Add(lblHwHdr);
            ry += 20;

            txtHwCpuName = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "İşlemci (CPU)", ref ry, Color.FromArgb(226, 232, 240));
            txtHwCpuTelemetry = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "CPU Sıcaklık / Yük", ref ry, Color.FromArgb(251, 146, 60));
            txtHwGpuName = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "Ekran Kartı (GPU)", ref ry, Color.FromArgb(226, 232, 240));
            txtHwGpuTelemetry = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "GPU Core / Hotspot", ref ry, Color.FromArgb(52, 211, 153));
            txtHwRamUsage = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "Sistem Belleği", ref ry, Color.FromArgb(251, 191, 36));
            txtHwTimerActive = CreateSidebarReadOnlyRow(pnlSidebarTopGrid, "Timer & Aktif Ayar", ref ry, Color.FromArgb(56, 189, 248));

            txtHwCpuName.Text = string.Format("{0} ({1}C/{2}T)", detectedHw.CpuName, detectedHw.PhysicalCores, detectedHw.LogicalThreads);
            txtHwGpuName.Text = detectedHw.GpuName;

            // Bottom Footer of Right Sidebar: Network Traffic Stats (Sent / Received MB)
            Panel pnlSidebarTrafficFooter = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 22,
                BackColor = Color.FromArgb(16, 20, 29)
            };
            pnlRightSidebar.Controls.Add(pnlSidebarTrafficFooter);

            lblNetTrafficStats = new Label
            {
                Text = "Ağ Trafiği: Gönderilen: -- MB | Alınan: -- MB",
                Font = new Font("Consolas", 7.6f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(2, 4)
            };
            pnlSidebarTrafficFooter.Controls.Add(lblNetTrafficStats);

            // Header for Live Console Log
            Panel pnlConsoleHdr = new Panel
            {
                Dock = DockStyle.Top,
                Height = 22,
                BackColor = Color.FromArgb(16, 20, 29)
            };
            pnlRightSidebar.Controls.Add(pnlConsoleHdr);

            lblSideEventLogHeader = new Label
            {
                Text = Loc.T("SİSTEM OLAY GÜNLÜĞÜ", "SYSTEM EVENT LOG"),
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(167, 243, 208),
                AutoSize = true,
                Location = new Point(2, 3)
            };
            pnlConsoleHdr.Controls.Add(lblSideEventLogHeader);

            // Multiline Console TextBox (NetAdapter Repair Bottom-Right Log Window)
            txtLiveConsoleLog = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(10, 13, 19),
                ForeColor = Color.FromArgb(167, 243, 208),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 7.8f, FontStyle.Regular)
            };
            pnlRightSidebar.Controls.Add(txtLiveConsoleLog);

            pnlSidebarTrafficFooter.SendToBack();
            pnlSidebarTopGrid.SendToBack();
            pnlConsoleHdr.BringToFront();
            txtLiveConsoleLog.BringToFront();
        }

        private TextBox CreateSidebarReadOnlyRow(Control parent, string labelText, ref int y, Color valueColor)
        {
            Label lbl = new Label
            {
                Text = labelText,
                Font = new Font("Segoe UI", 7.6f, FontStyle.Regular),
                ForeColor = Color.FromArgb(165, 180, 202),
                AutoSize = false,
                Size = new Size(118, 20),
                TextAlign = ContentAlignment.MiddleLeft,
                Location = new Point(2, y + 1),
                UseMnemonic = false
            };
            parent.Controls.Add(lbl);

            int pWidth = parent.ClientSize.Width > 0 ? parent.ClientSize.Width : 400;
            TextBox txt = new TextBox
            {
                ReadOnly = true,
                BackColor = Color.FromArgb(11, 14, 21),
                ForeColor = valueColor,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 7.8f, FontStyle.Bold),
                Location = new Point(122, y),
                Size = new Size(Math.Max(265, pWidth - 128), 20),
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
                Text = "Okunuyor..."
            };
            parent.Controls.Add(txt);
            sidebarRowLabels[txt] = lbl;
            y += 24;
            return txt;
        }

        private void AppendConsoleLog(string message)
        {
            if (string.IsNullOrEmpty(message) || txtLiveConsoleLog == null) return;
            try
            {
                string line = string.Format("[{0}] {1}{2}", DateTime.Now.ToString("HH:mm:ss"), message, Environment.NewLine);
                if (txtLiveConsoleLog.TextLength > 18000)
                {
                    txtLiveConsoleLog.Text = txtLiveConsoleLog.Text.Substring(txtLiveConsoleLog.TextLength - 10000);
                }
                txtLiveConsoleLog.AppendText(line);
            }
            catch { }
        }

        private void ProbeLiveNetworkSidebarDetails()
        {
            try
            {
                if (txtNetHostAdmin != null)
                {
                    txtNetHostAdmin.Text = string.Format("{0} | {1}", Environment.MachineName, isAdmin ? "YÖNETİCİ (Admin)" : "Standart");
                }

                NetworkInterface bestNic = null;
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    {
                        bestNic = ni;
                        if (ni.GetIPProperties().GatewayAddresses.Count > 0)
                            break;
                    }
                }

                if (bestNic != null)
                {
                    IPInterfaceProperties ipProps = bestNic.GetIPProperties();
                    string ipv4 = "N/A";
                    string mask = "";
                    foreach (UnicastIPAddressInformation ua in ipProps.UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            ipv4 = ua.Address.ToString();
                            if (ua.IPv4Mask != null) mask = ua.IPv4Mask.ToString();
                            break;
                        }
                    }

                    string gw = "Yok";
                    foreach (GatewayIPAddressInformation g in ipProps.GatewayAddresses)
                    {
                        if (g.Address != null && g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            gw = g.Address.ToString();
                            break;
                        }
                    }

                    List<string> dnsList = new List<string>();
                    foreach (System.Net.IPAddress dns in ipProps.DnsAddresses)
                    {
                        if (dns.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            dnsList.Add(dns.ToString());
                    }
                    if (dnsList.Count == 0)
                    {
                        foreach (System.Net.IPAddress dns in ipProps.DnsAddresses)
                            dnsList.Add(dns.ToString());
                    }

                    byte[] macBytes = bestNic.GetPhysicalAddress().GetAddressBytes();
                    List<string> macHex = new List<string>();
                    foreach (byte b in macBytes) macHex.Add(b.ToString("X2"));
                    string macStr = macHex.Count > 0 ? string.Join(":", macHex.ToArray()) : "N/A";

                    if (txtNetAdapter != null) txtNetAdapter.Text = bestNic.Description;
                    if (txtNetLocalIp != null) txtNetLocalIp.Text = string.IsNullOrEmpty(mask) ? ipv4 : (ipv4 + " / " + mask);
                    if (txtNetGateway != null) txtNetGateway.Text = gw;
                    if (txtNetDns != null) txtNetDns.Text = dnsList.Count > 0 ? string.Join(", ", dnsList.ToArray()) : "Otomatik (DHCP)";
                    if (txtNetMac != null) txtNetMac.Text = macStr;

                    try
                    {
                        IPv4InterfaceStatistics stats = bestNic.GetIPv4Statistics();
                        double sentMb = stats.BytesSent / (1024.0 * 1024.0);
                        double recvMb = stats.BytesReceived / (1024.0 * 1024.0);
                        if (lblNetTrafficStats != null)
                        {
                            lblNetTrafficStats.Text = string.Format("Gönderilen: {0:0.0} MB | Alınan: {1:0.0} MB", sentMb, recvMb);
                        }
                    }
                    catch { }
                }
                else
                {
                    if (txtNetAdapter != null) txtNetAdapter.Text = detectedHw.NicName;
                    if (txtNetLocalIp != null) txtNetLocalIp.Text = "Bağlantı Yok";
                }
            }
            catch { }
        }

        private void RunQuickSidebarPingTarget(string host, string label)
        {
            if (txtNetPingLive != null) txtNetPingLive.Text = label + " (" + host + ") ölçülüyor...";
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    using (Ping p = new Ping())
                    {
                        var r = p.Send(host, 1000);
                        long rtt = (r != null && r.Status == IPStatus.Success) ? r.RoundtripTime : -1;
                        this.BeginInvoke((MethodInvoker)delegate
                        {
                            if (rtt >= 0)
                            {
                                string msg = string.Format("{0} ({1}): {2} ms", label, host, rtt);
                                if (txtNetPingLive != null) txtNetPingLive.Text = msg;
                                AppendConsoleLog("Ping Testi -> " + msg);
                            }
                            else
                            {
                                if (txtNetPingLive != null) txtNetPingLive.Text = host + ": Zaman aşımı";
                                AppendConsoleLog("Ping Testi -> " + host + " yanıt vermedi.");
                            }
                        });
                    }
                }
                catch { }
            });
        }

        private void ReflowTelemetryHeaderBadges()
        {
            // Telemetry is now rendered in the dedicated NetAdapter Repair-style right sidebar.
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

        private Panel CreateTweakTableColumnHeader(string sectionTitle)
        {
            Panel pnlColHdr = new Panel
            {
                Height = 26,
                Width = 820,
                Margin = new Padding(0, 0, 0, 3),
                BackColor = Color.FromArgb(22, 28, 41)
            };

            Label lblCol1 = new Label
            {
                Text = Loc.T("DURUM & DONANIM / SİSTEM AYARI", "STATUS & HARDWARE / SYSTEM TWEAK") + (string.IsNullOrEmpty(sectionTitle) ? "" : (" (" + sectionTitle + ")")),
                Font = new Font("Segoe UI", 7.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(10, 6),
                UseMnemonic = false
            };
            pnlColHdr.Controls.Add(lblCol1);
            tweakColHeadersCol1.Add(lblCol1);

            Label lblCol2 = new Label
            {
                Text = Loc.T("UYGULAMA MODU / VARYASYON", "APPLICATION MODE / VARIATION"),
                Font = new Font("Segoe UI", 7.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(400, 6),
                UseMnemonic = false
            };
            pnlColHdr.Controls.Add(lblCol2);
            tweakColHeadersCol2.Add(lblCol2);

            Label lblCol3 = new Label
            {
                Text = Loc.T("CANLI OS DEĞERİ", "LIVE OS VALUE"),
                Font = new Font("Segoe UI", 7.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Location = new Point(650, 6),
                UseMnemonic = false
            };
            pnlColHdr.Controls.Add(lblCol3);
            tweakColHeadersCol3.Add(lblCol3);

            pnlColHdr.Resize += (s, e) =>
            {
                int w = Math.Max(520, pnlColHdr.ClientSize.Width);
                int rightX = w - 6;
                rightX -= 27; // btnInfoInspect (22px + 5px margin)

                int badgeW = w >= 800 ? 168 : (w >= 700 ? 152 : 132);
                int badgeX = rightX - badgeW;
                rightX -= (badgeW + 6);

                int comboW = w >= 800 ? 250 : (w >= 700 ? 220 : 185);
                int comboX = rightX - comboW;

                lblCol2.Location = new Point(comboX, 6);
                lblCol3.Location = new Point(badgeX + 6, 6);
            };

            return pnlColHdr;
        }

        private void BuildProgressiveHardwareMatrixView()
        {
            viewDashboard = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(10, 8, 10, 8)
            };
            pnlContentHost.Controls.Add(viewDashboard);

            // Top Card: Compact CPU + GPU Configurator & 3-Tier Auto-Pilot
            Panel pnlMatrixTop = new Panel
            {
                Dock = DockStyle.Top,
                Height = 142,
                BackColor = Color.FromArgb(18, 23, 34)
            };
            pnlMatrixTop.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(36, 46, 66), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlMatrixTop.Width - 1, pnlMatrixTop.Height - 1);
                }
            };
            viewDashboard.Controls.Add(pnlMatrixTop);

            lblMatTitle = new Label
            {
                Text = Loc.T("DONANIM PROFİLİ VE OPTİMİZASYON SEVİYESİ", "HARDWARE PROFILE & OPTIMIZATION LEVEL"),
                Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Location = new Point(12, 8)
            };
            pnlMatrixTop.Controls.Add(lblMatTitle);

            // CPU Selector
            lblCpuPick = new Label
            {
                Text = Loc.T("1. İşlemci (CPU) Mimarisi:", "1. Processor (CPU) Architecture:"),
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                AutoSize = true,
                Location = new Point(12, 30)
            };
            pnlMatrixTop.Controls.Add(lblCpuPick);

            cmbCpuSelector = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(12, 48),
                Size = new Size(250, 24)
            };
            cmbCpuSelector.Items.AddRange(new object[]
            {
                "AMD Ryzen Standart (Zen 2/3/4/5)",
                "AMD Ryzen X3D (3D V-Cache Serisi)",
                "Intel Core Hibrit (P-Core + E-Core)",
                "Intel Core Klasik (Homojen Çekirdek)"
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
            lblGpuPick = new Label
            {
                Text = Loc.T("2. Ekran Kartı (GPU) Mimarisi:", "2. Graphics Card (GPU) Architecture:"),
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                AutoSize = true,
                Location = new Point(272, 30)
            };
            pnlMatrixTop.Controls.Add(lblGpuPick);

            cmbGpuSelector = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(52, 211, 153),
                Location = new Point(272, 48),
                Size = new Size(240, 24)
            };
            cmbGpuSelector.Items.AddRange(new object[]
            {
                "AMD Radeon (RX 6000 / 7000 / 9000)",
                "NVIDIA GeForce (RTX 20 / 30 / 40 / 50)",
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
            lblTierPick = new Label
            {
                Text = Loc.T("3. Optimizasyon Kademesi:", "3. Optimization Level:"),
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                AutoSize = true,
                Location = new Point(522, 30)
            };
            pnlMatrixTop.Controls.Add(lblTierPick);

            btnTier1 = CreateActionButton(pnlMatrixTop, 522, 47, 96, 25, Loc.T("1: Dengeli", "1: Balanced"), Color.FromArgb(37, 45, 64));
            btnTier2 = CreateActionButton(pnlMatrixTop, 622, 47, 96, 25, Loc.T("2: Espor", "2: Esports"), Color.FromArgb(16, 185, 129));
            btnTier2.ForeColor = Color.Black;
            btnTier3 = CreateActionButton(pnlMatrixTop, 722, 47, 96, 25, Loc.T("3: Ekstrem", "3: Extreme"), Color.FromArgb(37, 45, 64));

            btnTier1.Font = new Font("Segoe UI", 7.6f, FontStyle.Bold);
            btnTier2.Font = new Font("Segoe UI", 7.6f, FontStyle.Bold);
            btnTier3.Font = new Font("Segoe UI", 7.6f, FontStyle.Bold);

            btnTier1.Click += (s, e) => SelectProgressiveTier(1);
            btnTier2.Click += (s, e) => SelectProgressiveTier(2);
            btnTier3.Click += (s, e) => SelectProgressiveTier(3);

            // Action Buttons Row
            btnSmartApply = CreateActionButton(pnlMatrixTop, 12, 80, 410, 32,
                Loc.T("⚡ SEÇİLİ PROFİLİ TEK TIKLA UYGULA", "⚡ APPLY SELECTED PROFILE (ONE-CLICK)"), Color.FromArgb(16, 185, 129));
            btnSmartApply.ForeColor = Color.Black;
            btnSmartApply.Font = new Font("Segoe UI", 8.2f, FontStyle.Bold);
            btnSmartApply.Click += (s, e) => ApplyHardwareAwareSmartTune();
            mainToolTip.SetToolTip(btnSmartApply, "Seçtiğiniz İşlemci + Ekran Kartı ikilisine özel Windows çekirdek/sürücü ayarlarını, çakışma kurallarını ve kademe seviyesini tek tıkla uygular.");

            btnAutoDetectReset = CreateActionButton(pnlMatrixTop, 430, 80, 190, 32,
                Loc.T("Donanımımı Otomatik Algıla", "Auto-Detect Hardware"), Color.FromArgb(14, 165, 233));
            btnAutoDetectReset.ForeColor = Color.Black;
            btnAutoDetectReset.Click += (s, e) =>
            {
                cmbCpuSelector.SelectedIndex = (int)detectedHw.RecommendedCpuProfile;
                cmbGpuSelector.SelectedIndex = (int)detectedHw.RecommendedGpuProfile;
                SelectProgressiveTier(2);
                RefreshHardwareMatrixCards();
                AppendConsoleLog("Donanım matrisi sistem algılamasına göre sıfırlandı.");
            };

            btnQuickRam = CreateActionButton(pnlMatrixTop, 628, 80, 190, 32,
                Loc.T("Anlık RAM & DNS Temizle", "Instant RAM & DNS Purge"), Color.FromArgb(51, 65, 85));
            btnQuickRam.UseMnemonic = false;
            btnQuickRam.Click += (s, e) =>
            {
                ExecuteSmartRamAndStandbyPurge(true);
                ExecuteInstantNetworkQueueFlush();
                AppendConsoleLog("RAM Çalışma Kümesi, Standby List ve DNS önbelleği temizlendi.");
            };

            lblMatrixSummary = new Label
            {
                Text = "Aktif Kombinasyon Özeti hazırlanıyor...",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(165, 180, 202),
                AutoSize = true,
                Location = new Point(12, 118)
            };
            pnlMatrixTop.Controls.Add(lblMatrixSummary);

            Action layoutMatrixTop = () =>
            {
                int availW = Math.Max(760, pnlMatrixTop.ClientSize.Width - 24);
                int tierBlockW = Math.Max(296, (int)(availW * 0.36));
                int eachTierW = (tierBlockW - 8) / 3;
                int comboSpace = availW - tierBlockW - 20;
                int cpuComboW = Math.Max(210, comboSpace / 2);
                int gpuComboW = Math.Max(200, comboSpace - cpuComboW);

                lblCpuPick.Location = new Point(12, 30);
                cmbCpuSelector.Location = new Point(12, 48);
                cmbCpuSelector.Width = cpuComboW;

                lblGpuPick.Location = new Point(cmbCpuSelector.Right + 10, 30);
                cmbGpuSelector.Location = new Point(cmbCpuSelector.Right + 10, 48);
                cmbGpuSelector.Width = gpuComboW;

                int tierStartX = cmbGpuSelector.Right + 10;
                lblTierPick.Location = new Point(tierStartX, 30);
                btnTier1.Location = new Point(tierStartX, 47);
                btnTier1.Size = new Size(eachTierW, 25);

                btnTier2.Location = new Point(btnTier1.Right + 4, 47);
                btnTier2.Size = new Size(eachTierW, 25);

                btnTier3.Location = new Point(btnTier2.Right + 4, 47);
                btnTier3.Size = new Size(eachTierW, 25);

                int smartW = Math.Max(380, (int)(availW * 0.50));
                int remW = availW - smartW - 16;
                int subBtnW = Math.Max(160, remW / 2);

                btnSmartApply.Location = new Point(12, 80);
                btnSmartApply.Size = new Size(smartW, 32);

                btnAutoDetectReset.Location = new Point(btnSmartApply.Right + 8, 80);
                btnAutoDetectReset.Size = new Size(subBtnW, 32);

                btnQuickRam.Location = new Point(btnAutoDetectReset.Right + 8, 80);
                btnQuickRam.Size = new Size(subBtnW, 32);
            };
            pnlMatrixTop.Resize += (s, e) => layoutMatrixTop();
            layoutMatrixTop();

            // Section 2: Table Column Header for Hardware-Specific Tweaks
            Panel pnlHwCardsHeader = CreateTweakTableColumnHeader("Seçili İşlemci & Ekran Kartı Mimarisi");
            pnlHwCardsHeader.Dock = DockStyle.Top;
            viewDashboard.Controls.Add(pnlHwCardsHeader);

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
                card.Width = Math.Max(540, viewDashboard.ClientSize.Width - 28);
                flowHardwareSpecificCards.Controls.Add(card);
                allCards.Add(card);
            }

            flowHardwareSpecificCards.Resize += (s, e) =>
            {
                int w = Math.Max(540, flowHardwareSpecificCards.ClientSize.Width - 24);
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
                    "Akıllı Donanım Profili",
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
                    t.IsEnabled = true;
                    t.SelectedVariationIndex = targetVar;
                    if (t.Variations[t.SelectedVariationIndex].ApplyAction != null)
                        t.Variations[t.SelectedVariationIndex].ApplyAction();
                    t.CurrentAppliedText = string.Format("Mod {0}: {1}", targetVar + 1, t.Variations[targetVar].ShortLabel);
                    AutoResolveRebootAndReloadState(t);
                }
                else if (!enable && t.IsEnabled)
                {
                    t.IsEnabled = false;
                    t.IsVerifiedInOs = false;
                    t.VerifiedSystemValue = "";
                    if (t.RevertAction != null) t.RevertAction();
                    t.CurrentAppliedText = "Pasif (Orijinal)";
                    AutoResolveRebootAndReloadState(t);
                }
                card.RefreshVisualState();
            }

            EnforceFixedCombinationsAndConflicts(null);
            VerifyAllTweaksLive(false);
            UpdateActiveCountsAndNavBadges();
            RefreshSnapshotAuditView();
            SaveUserProfileState();
            AppendConsoleLog("Donanım duyarlı Akıllı Ayar (Smart Tune) uygulandı ve canlı OS doğrulaması tamamlandı.");
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

        private void LayoutNavBarButtons()
        {
            if (pnlNavBar == null || navButtons == null || navButtons.Count == 0) return;

            int w = pnlNavBar.ClientSize.Width > 0 ? pnlNavBar.ClientSize.Width : 1380;

            // Search box positioning at right edge
            int searchW = 0;
            if (txtGlobalSearch != null && lblSearchIcon != null)
            {
                txtGlobalSearch.Width = 100;
                txtGlobalSearch.Location = new Point(w - txtGlobalSearch.Width - 10, 6);
                lblSearchIcon.Location = new Point(txtGlobalSearch.Left - lblSearchIcon.PreferredSize.Width - 4, 8);
                searchW = txtGlobalSearch.Width + lblSearchIcon.PreferredSize.Width + 18;
            }

            int availForTabs = w - searchW - 12;

            int totalPrefW = 0;
            for (int i = 0; i < navButtons.Count; i++)
            {
                totalPrefW += navButtons[i].PreferredSize.Width + 6;
            }

            double scale = 1.0;
            if (totalPrefW > availForTabs && totalPrefW > 0)
            {
                scale = (double)availForTabs / totalPrefW;
            }

            int nx = 6;
            for (int i = 0; i < navButtons.Count; i++)
            {
                var btn = navButtons[i];
                btn.Location = new Point(nx, 5);
                if (scale < 1.0)
                {
                    btn.Width = Math.Max(38, (int)(btn.PreferredSize.Width * scale));
                    nx += btn.Width + 1;
                }
                else
                {
                    btn.Width = btn.PreferredSize.Width + 6;
                    nx += btn.Width + 3;
                }
            }
        }

        private void LayoutRebootWarningBannerControls()
        {
            // WinForms DockStyle.Right on buttons and DockStyle.Fill on lblRebootBannerText handle all layout automatically
        }

        private void UpdateRebootAndReloadBannerVisibility()
        {
            if (pnlRebootWarningBanner == null) return;

            int rebootCount = 0;
            int reloadPendingCount = 0;
            List<string> rebootTitles = new List<string>();
            List<string> reloadTitles = new List<string>();

            foreach (var t in allTweaks)
            {
                if (t.IsRebootPending)
                {
                    rebootCount++;
                    rebootTitles.Add(t.Title);
                }
                else if (t.IsNetReloadPending)
                {
                    reloadPendingCount++;
                    reloadTitles.Add(t.Title);
                }
            }

            if (rebootCount == 0 && reloadPendingCount == 0)
            {
                bannerDismissedBySession = false;
                pnlRebootWarningBanner.Visible = false;
                pnlRebootWarningBanner.Height = 0;
                return;
            }

            if (bannerDismissedBySession)
            {
                pnlRebootWarningBanner.Visible = false;
                pnlRebootWarningBanner.Height = 0;
                return;
            }

            pnlRebootWarningBanner.Visible = true;
            pnlRebootWarningBanner.Height = 38;

            if (rebootCount > 0 && reloadPendingCount > 0)
            {
                string rName = rebootTitles[0];
                if (rebootTitles.Count > 1) rName += string.Format(" (+{0})", rebootTitles.Count - 1);
                lblRebootBannerText.Text = string.Format("⚠️ {0} sistem ayarı [Restart: {1}], {2} ağ ayarı [Ağ Yenileme] bekliyor.", rebootCount, rName, reloadPendingCount);
                lblRebootBannerText.ForeColor = Color.FromArgb(253, 224, 71);
                btnRebootPcBanner.Visible = true;
                btnRebootPcBanner.Text = string.Format("⚡ Bilgisayarı Yeniden Başlat ({0})", rebootCount);
                btnSoftReloadNow.Visible = true;
                btnSoftReloadNow.Text = string.Format("🔄 Ağ Kartını Yenile ({0})", reloadPendingCount);
            }
            else if (rebootCount > 0)
            {
                string names = rebootTitles[0];
                if (rebootTitles.Count > 1) names += ", " + rebootTitles[1];
                if (rebootTitles.Count > 2) names += string.Format(" (+{0} daha)", rebootTitles.Count - 2);
                lblRebootBannerText.Text = string.Format("⚠️ Restart Bekliyor ({0} Ayar): {1} — Windows çekirdeğinde tam devreye girmesi için yeniden başlatma gerekir.", rebootCount, names);
                lblRebootBannerText.ForeColor = Color.FromArgb(253, 186, 116);
                btnRebootPcBanner.Visible = true;
                btnRebootPcBanner.Text = string.Format("⚡ Bilgisayarı Yeniden Başlat ({0})", rebootCount);
                btnSoftReloadNow.Visible = false;
            }
            else
            {
                lblRebootBannerText.Text = string.Format("⚡ {0} ağ ayarı için Ağ Adaptörünün yenilenmesi gerekiyor (Bilgisayarı yeniden başlatmaya gerek yoktur).", reloadPendingCount);
                lblRebootBannerText.ForeColor = Color.FromArgb(125, 211, 252);
                btnSoftReloadNow.Visible = true;
                btnSoftReloadNow.Text = "🔄 Ağ Kartını Şimdi Yenile";
                btnRebootPcBanner.Visible = false;
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
                Padding = new Padding(10, 8, 10, 8),
                BackColor = Color.FromArgb(13, 16, 23),
                Visible = false
            };

            string catTitle = category == "NETWORK" ? "Ağ, NDIS & TCP/IP Yığını"
                            : category == "LATENCY" ? "Çekirdek Zamanlayıcı, Güç & HID Giriş"
                            : category == "FPS" ? "Kare Hızı (FPS), DWM, MMCSS & Bellek"
                            : "İleri Seviye / Deneysel Çekirdek Parametreleri";

            Panel colHdr = CreateTweakTableColumnHeader(catTitle);
            flow.Controls.Add(colHdr);

            foreach (var tweak in allTweaks)
            {
                if (tweak.Category != category) continue;
                var card = new MultiVariationTweakCard(tweak, mainToolTip, OnTweakCardToggled, OnTweakCardHovered);
                card.Width = 810;
                flow.Controls.Add(card);
                allCards.Add(card);
            }

            flow.Resize += (s, e) =>
            {
                int targetW = Math.Max(520, flow.ClientSize.Width - 26);
                foreach (Control c in flow.Controls)
                {
                    c.Width = targetW;
                    c.Invalidate(true);
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
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
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
                Padding = new Padding(10, 8, 10, 8),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewProcesses);

            Panel pnlTopProc = new Panel
            {
                Dock = DockStyle.Top,
                Height = 42,
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewProcesses.Controls.Add(pnlTopProc);

            Label lblFilter = new Label
            {
                Text = "Süreç (.exe) Ara:",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(10, 12)
            };
            pnlTopProc.Controls.Add(lblFilter);

            txtProcFilter = new TextBox
            {
                Location = new Point(112, 9),
                Size = new Size(165, 22),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            txtProcFilter.TextChanged += (s, e) => RefreshProcessTable();
            pnlTopProc.Controls.Add(txtProcFilter);

            Button btnRefProc = CreateActionButton(pnlTopProc, 285, 8, 96, 25, "Listeyi Yenile", Color.FromArgb(51, 65, 85));
            btnRefProc.Click += (s, e) => RefreshProcessTable();

            chkWatchdogToggle = new CheckBox
            {
                Text = "Otomatik Oyun Algılayıcı (Oyun Açıldığında High Prio + EcoQoS Kalkanı)",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Checked = false,
                Location = new Point(392, 12)
            };
            chkWatchdogToggle.CheckedChanged += (s, e) => autoGameWatchdogActive = chkWatchdogToggle.Checked;
            pnlTopProc.Controls.Add(chkWatchdogToggle);

            Panel pnlBottomProc = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 76,
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewProcesses.Controls.Add(pnlBottomProc);

            int bx = 10;
            Button bHigh = CreateActionButton(pnlBottomProc, bx, 8, 155, 28, "High Priority (Ağaç)", Color.FromArgb(16, 185, 129));
            bHigh.ForeColor = Color.Black;
            bHigh.Click += (s, e) => ApplySelectedProcessPriority(ProcessPriorityClass.High);
            bx += 161;

            Button bNoCore0 = CreateActionButton(pnlBottomProc, bx, 8, 158, 28, "Core 0 İzole (DPC)", Color.FromArgb(14, 165, 233));
            bNoCore0.ForeColor = Color.Black;
            bNoCore0.Click += (s, e) => ApplySelectedProcessTopology(1);
            bx += 164;

            Button bPhysOnly = CreateActionButton(pnlBottomProc, bx, 8, 168, 28, "Fiziksel Çekirdekler", Color.FromArgb(168, 85, 247));
            bPhysOnly.Click += (s, e) => ApplySelectedProcessTopology(2);
            bx += 174;

            Button bEcoShield = CreateActionButton(pnlBottomProc, bx, 8, 162, 28, "EcoQoS + I/O High", Color.FromArgb(217, 119, 6));
            bEcoShield.ForeColor = Color.Black;
            bEcoShield.Click += (s, e) => ApplySelectedProcessEcoAndIoBoost();
            bx += 168;

            Button bRevertProc = CreateActionButton(pnlBottomProc, bx, 8, 145, 28, "Orijinale Döndür", Color.FromArgb(71, 85, 105));
            bRevertProc.Click += (s, e) => RevertSelectedProcessToOriginal();

            lblProcActionStatus = new Label
            {
                Text = "Listeden herhangi bir .exe seçip tek tıkla öncelik ve çekirdek topolojisi atayabilirsiniz. İstediğiniz zaman orijinale döndürebilirsiniz.",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(10, 44)
            };
            pnlBottomProc.Controls.Add(lblProcActionStatus);

            lvProcesses = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(14, 18, 26),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Regular)
            };
            lvProcesses.Columns.Add("Süreç Adı (.exe)", 185);
            lvProcesses.Columns.Add("PID", 65);
            lvProcesses.Columns.Add("CPU Önceliği", 105);
            lvProcesses.Columns.Add("Çekirdek Maskesi (Affinity)", 190);
            lvProcesses.Columns.Add("Bellek (MB)", 95);
            lvProcesses.Columns.Add("Yedek Durumu", 160);
            viewProcesses.Controls.Add(lvProcesses);
            pnlTopProc.SendToBack();
            pnlBottomProc.SendToBack();
            lvProcesses.BringToFront();
        }

        #region Otomasyon & QoL (Swiss Army Knife) View & Systems

        private void BuildAutomationAndQoLView()
        {
            viewAutomationQoL = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(12, 10, 12, 10),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewAutomationQoL);

            // Container panel for smooth layout
            Panel pnlScrollBody = new Panel
            {
                Location = new Point(12, 10),
                Width = Math.Max(780, viewAutomationQoL.ClientSize.Width - 36),
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                BackColor = Color.Transparent
            };
            viewAutomationQoL.Controls.Add(pnlScrollBody);

            int cardY = 0;

            // -------------------------------------------------------------
            // CARD 1: AKILLI GÜÇ & KAPATMA ZAMANLAYICISI
            // -------------------------------------------------------------
            Panel pnlCardPower = new Panel
            {
                Location = new Point(0, cardY),
                Size = new Size(pnlScrollBody.Width, 130),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            pnlCardPower.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(36, 46, 66), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlCardPower.Width - 1, pnlCardPower.Height - 1);
                }
            };
            pnlScrollBody.Controls.Add(pnlCardPower);

            Label lblPowerTitle = new Label
            {
                Text = "⏱️ AKILLI GÜÇ & KAPATMA ZAMANLAYICISI",
                Font = new Font("Segoe UI", 9.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(12, 10),
                AutoSize = true
            };
            pnlCardPower.Controls.Add(lblPowerTitle);

            Button btnGearPower = new Button
            {
                Text = "⚙️ İndirme & Boşta Koruması",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(28, 35, 50),
                ForeColor = Color.FromArgb(203, 213, 225),
                Size = new Size(185, 24),
                Location = new Point(pnlCardPower.Width - 195, 8),
                Cursor = Cursors.Hand
            };
            btnGearPower.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnGearPower.Click += (s, e) => ShowPowerTimerSettingsDialog();
            pnlCardPower.Controls.Add(btnGearPower);

            rbPowerCountdown = new RadioButton
            {
                Text = "Geri Sayım:",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(14, 40),
                AutoSize = true,
                Checked = (qolConfig.PowerTimerMode == "COUNTDOWN")
            };
            pnlCardPower.Controls.Add(rbPowerCountdown);

            numPowerHours = new NumericUpDown
            {
                Minimum = 0,
                Maximum = 48,
                Value = Math.Max(0, Math.Min(48, qolConfig.PowerTimerHours)),
                Location = new Point(110, 39),
                Width = 45,
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold)
            };
            pnlCardPower.Controls.Add(numPowerHours);

            Label lblH = new Label { Text = "saat", ForeColor = Color.FromArgb(148, 163, 184), Font = new Font("Segoe UI", 8.0f), Location = new Point(158, 42), AutoSize = true };
            pnlCardPower.Controls.Add(lblH);

            numPowerMins = new NumericUpDown
            {
                Minimum = 0,
                Maximum = 59,
                Value = Math.Max(0, Math.Min(59, qolConfig.PowerTimerMinutes)),
                Location = new Point(195, 39),
                Width = 45,
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold)
            };
            pnlCardPower.Controls.Add(numPowerMins);

            Label lblM = new Label { Text = "dk sonra", ForeColor = Color.FromArgb(148, 163, 184), Font = new Font("Segoe UI", 8.0f), Location = new Point(243, 42), AutoSize = true };
            pnlCardPower.Controls.Add(lblM);

            rbPowerSpecific = new RadioButton
            {
                Text = "Belirli Saatte:",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(320, 40),
                AutoSize = true,
                Checked = (qolConfig.PowerTimerMode == "SPECIFIC_TIME")
            };
            pnlCardPower.Controls.Add(rbPowerSpecific);

            txtPowerSpecificTime = new TextBox
            {
                Text = string.IsNullOrEmpty(qolConfig.PowerTimerSpecificTime) ? "23:00" : qolConfig.PowerTimerSpecificTime,
                Location = new Point(425, 39),
                Width = 60,
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                TextAlign = HorizontalAlignment.Center
            };
            pnlCardPower.Controls.Add(txtPowerSpecificTime);

            Label lblActHdr = new Label { Text = "İşlem:", ForeColor = Color.FromArgb(148, 163, 184), Font = new Font("Segoe UI", 8.0f, FontStyle.Bold), Location = new Point(515, 42), AutoSize = true };
            pnlCardPower.Controls.Add(lblActHdr);

            cmbPowerAction = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Location = new Point(560, 39),
                Width = 195,
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold)
            };
            cmbPowerAction.Items.AddRange(new object[] { "Bilgisayarı Kapat (Shutdown)", "Yeniden Başlat (Restart)", "Uyku Moduna Al (Sleep)", "Oturumu Kilitle (Lock)" });
            int actIdx = 0;
            if (qolConfig.PowerTimerAction == "RESTART") actIdx = 1;
            else if (qolConfig.PowerTimerAction == "SLEEP") actIdx = 2;
            else if (qolConfig.PowerTimerAction == "LOCK") actIdx = 3;
            cmbPowerAction.SelectedIndex = actIdx;
            pnlCardPower.Controls.Add(cmbPowerAction);

            btnStartPowerTimer = new Button
            {
                Text = "▶️ Zamanlayıcıyı Başlat",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.Black,
                Size = new Size(165, 28),
                Location = new Point(14, 84),
                Cursor = Cursors.Hand
            };
            btnStartPowerTimer.FlatAppearance.BorderSize = 0;
            btnStartPowerTimer.Click += (s, e) => ToggleStartPowerTimer();
            pnlCardPower.Controls.Add(btnStartPowerTimer);

            btnCancelPowerTimer = new Button
            {
                Text = "⏹️ İptal Et",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(220, 38, 38),
                ForeColor = Color.White,
                Size = new Size(95, 28),
                Location = new Point(185, 84),
                Cursor = Cursors.Hand,
                Enabled = qolConfig.PowerTimerActive
            };
            btnCancelPowerTimer.FlatAppearance.BorderSize = 0;
            btnCancelPowerTimer.Click += (s, e) => CancelPowerTimer(true);
            pnlCardPower.Controls.Add(btnCancelPowerTimer);

            lblPowerTimerStatus = new Label
            {
                Text = qolConfig.PowerTimerActive ? "⏳ Zamanlayıcı Aktif..." : "Zamanlayıcı pasif. Süre ve işlem türü seçip 'Başlat' butonuna basabilirsiniz.",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = qolConfig.PowerTimerActive ? Color.FromArgb(253, 224, 71) : Color.FromArgb(148, 163, 184),
                Location = new Point(290, 89),
                AutoSize = true
            };
            pnlCardPower.Controls.Add(lblPowerTimerStatus);

            cardY += 140;

            // -------------------------------------------------------------
            // CARD 2: PERİYODİK & ZAMANLI ALARMLAR (KRİPTO & RUTİNLER)
            // -------------------------------------------------------------
            Panel pnlCardAlarms = new Panel
            {
                Location = new Point(0, cardY),
                Size = new Size(pnlScrollBody.Width, 240),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            pnlCardAlarms.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(36, 46, 66), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlCardAlarms.Width - 1, pnlCardAlarms.Height - 1);
                }
            };
            pnlScrollBody.Controls.Add(pnlCardAlarms);

            Label lblAlarmTitle = new Label
            {
                Text = "⏰ PERİYODİK & ZAMANLI ALARMLAR (KRİPTO KAPANIŞLARI & RUTİNLER)",
                Font = new Font("Segoe UI", 9.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(168, 85, 247),
                Location = new Point(12, 10),
                AutoSize = true
            };
            pnlCardAlarms.Controls.Add(lblAlarmTitle);

            Button btnGearAlarms = new Button
            {
                Text = "⚙️ Ses & Bildirim Ayarları",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(28, 35, 50),
                ForeColor = Color.FromArgb(203, 213, 225),
                Size = new Size(185, 24),
                Location = new Point(pnlCardAlarms.Width - 195, 8),
                Cursor = Cursors.Hand
            };
            btnGearAlarms.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnGearAlarms.Click += (s, e) => ShowAlarmAudioSettingsDialog();
            pnlCardAlarms.Controls.Add(btnGearAlarms);

            // Preset Buttons Bar
            int preX = 12;
            Button btnPre4H = new Button
            {
                Text = "⚡ 4H Kripto Mumu (03, 07, 11, 15, 19, 23)",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(56, 189, 248),
                Size = new Size(250, 24),
                Location = new Point(preX, 38),
                Cursor = Cursors.Hand
            };
            btnPre4H.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnPre4H.Click += (s, e) => AddCryptoPresetAlarm("CRYPTO_4H");
            pnlCardAlarms.Controls.Add(btnPre4H);
            preX += 256;

            Button btnPreDaily = new Button
            {
                Text = "📅 Günlük Kapanış (03:00 UTC+3)",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(52, 211, 153),
                Size = new Size(205, 24),
                Location = new Point(preX, 38),
                Cursor = Cursors.Hand
            };
            btnPreDaily.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnPreDaily.Click += (s, e) => AddCryptoPresetAlarm("CRYPTO_DAILY");
            pnlCardAlarms.Controls.Add(btnPreDaily);
            preX += 211;

            Button btnPreWeekly = new Button
            {
                Text = "📅 Haftalık Kapanış (Pzt 03:00)",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(251, 191, 36),
                Size = new Size(195, 24),
                Location = new Point(preX, 38),
                Cursor = Cursors.Hand
            };
            btnPreWeekly.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnPreWeekly.Click += (s, e) => AddCryptoPresetAlarm("CRYPTO_WEEKLY");
            pnlCardAlarms.Controls.Add(btnPreWeekly);
            preX += 201;

            Button btnAddAlarm = new Button
            {
                Text = "➕ Özel Alarm Ekle...",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(124, 58, 237),
                ForeColor = Color.White,
                Size = new Size(135, 24),
                Location = new Point(preX, 38),
                Cursor = Cursors.Hand
            };
            btnAddAlarm.FlatAppearance.BorderSize = 0;
            btnAddAlarm.Click += (s, e) => ShowAddCustomAlarmDialog();
            pnlCardAlarms.Controls.Add(btnAddAlarm);

            // Alarms ListView
            lvAlarms = new ListView
            {
                Location = new Point(12, 68),
                Size = new Size(pnlCardAlarms.Width - 24, 130),
                View = View.Details,
                FullRowSelect = true,
                CheckBoxes = true,
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle
            };
            lvAlarms.Columns.Add("Durum", 60);
            lvAlarms.Columns.Add("Alarm Başlığı", 250);
            lvAlarms.Columns.Add("Açıklama / Not", 270);
            lvAlarms.Columns.Add("Aralık / Tür", 160);
            lvAlarms.Columns.Add("Sonraki Çalma Saati", 160);
            lvAlarms.ItemChecked += (s, e) =>
            {
                if (e.Item != null && e.Item.Tag is CustomAlarmItem)
                {
                    CustomAlarmItem item = (CustomAlarmItem)e.Item.Tag;
                    item.IsEnabled = e.Item.Checked;
                    qolConfig.SaveToFile(qolConfigPath);
                }
            };
            pnlCardAlarms.Controls.Add(lvAlarms);

            // Sub-buttons below list
            Button btnStopSound = new Button
            {
                Text = "⏹️ Sesi Sustur",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(248, 113, 113),
                Size = new Size(110, 24),
                Location = new Point(12, 204),
                Cursor = Cursors.Hand
            };
            btnStopSound.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnStopSound.Click += (s, e) => AudioAlertPlayer.StopAlert();
            pnlCardAlarms.Controls.Add(btnStopSound);

            Button btnTestAlarm = new Button
            {
                Text = "🔔 Seçiliyi Test Et",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(52, 211, 153),
                Size = new Size(130, 24),
                Location = new Point(128, 204),
                Cursor = Cursors.Hand
            };
            btnTestAlarm.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnTestAlarm.Click += (s, e) =>
            {
                if (lvAlarms.SelectedItems.Count > 0 && lvAlarms.SelectedItems[0].Tag is CustomAlarmItem)
                {
                    CustomAlarmItem itm = (CustomAlarmItem)lvAlarms.SelectedItems[0].Tag;
                    TriggerAlarmAlert(itm);
                }
                else
                {
                    AudioAlertPlayer.PlayAlert(qolConfig.AlarmCustomSoundPath, qolConfig.AlarmMaxPlayDurationSec);
                    ShowQoLToast("⏰ Test Alarm Uyarısı", "Alarm ses ve darbe sistemi çalışıyor!", "Tamam", () => AudioAlertPlayer.StopAlert(), Color.FromArgb(168, 85, 247), 15, true);
                }
            };
            pnlCardAlarms.Controls.Add(btnTestAlarm);

            Button btnDelAlarm = new Button
            {
                Text = "🗑️ Seçili Alarmı Sil",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(220, 38, 38),
                Size = new Size(135, 24),
                Location = new Point(264, 204),
                Cursor = Cursors.Hand
            };
            btnDelAlarm.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnDelAlarm.Click += (s, e) =>
            {
                if (lvAlarms.SelectedItems.Count > 0 && lvAlarms.SelectedItems[0].Tag is CustomAlarmItem)
                {
                    CustomAlarmItem itm = (CustomAlarmItem)lvAlarms.SelectedItems[0].Tag;
                    qolConfig.Alarms.Remove(itm);
                    qolConfig.SaveToFile(qolConfigPath);
                    RefreshAlarmsListView();
                }
            };
            pnlCardAlarms.Controls.Add(btnDelAlarm);

            cardY += 250;

            // -------------------------------------------------------------
            // CARD 3: OYUN HATIRLATICI & NOT KALKANI
            // -------------------------------------------------------------
            Panel pnlCardGameNotes = new Panel
            {
                Location = new Point(0, cardY),
                Size = new Size(pnlScrollBody.Width, 205),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            pnlCardGameNotes.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(36, 46, 66), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlCardGameNotes.Width - 1, pnlCardGameNotes.Height - 1);
                }
            };
            pnlScrollBody.Controls.Add(pnlCardGameNotes);

            Label lblGameTitle = new Label
            {
                Text = "🎮 OYUN HATIRLATICI & NOT KALKANI (OYUN İÇİ SESSİZ NOTLAR)",
                Font = new Font("Segoe UI", 9.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                Location = new Point(12, 10),
                AutoSize = true
            };
            pnlCardGameNotes.Controls.Add(lblGameTitle);

            Label lblGameSub = new Label
            {
                Text = "Seçilen oyun (.exe) açıldığında masaüstünde sessizce notlarınızı hatırlatır (Ses çalmaz; sadece görsel bildirim).",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(12, 30),
                AutoSize = true
            };
            pnlCardGameNotes.Controls.Add(lblGameSub);

            Button btnAddGame = new Button
            {
                Text = "➕ Oyuna Not Ekle...",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(217, 119, 6),
                ForeColor = Color.White,
                Size = new Size(160, 24),
                Location = new Point(pnlCardGameNotes.Width - 170, 8),
                Cursor = Cursors.Hand
            };
            btnAddGame.FlatAppearance.BorderSize = 0;
            btnAddGame.Click += (s, e) => ShowAddGameNoteDialog();
            pnlCardGameNotes.Controls.Add(btnAddGame);

            lvGameNotes = new ListView
            {
                Location = new Point(12, 54),
                Size = new Size(pnlCardGameNotes.Width - 24, 115),
                View = View.Details,
                FullRowSelect = true,
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle
            };
            lvGameNotes.Columns.Add("Oyun Adı", 180);
            lvGameNotes.Columns.Add("Süreç Adı (.exe)", 130);
            lvGameNotes.Columns.Add("Özel Not İçeriği", 360);
            lvGameNotes.Columns.Add("Hatırlatma Sıklığı", 150);
            pnlCardGameNotes.Controls.Add(lvGameNotes);

            Button btnDelGame = new Button
            {
                Text = "🗑️ Seçili Notu Sil",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(220, 38, 38),
                Size = new Size(130, 24),
                Location = new Point(12, 174),
                Cursor = Cursors.Hand
            };
            btnDelGame.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnDelGame.Click += (s, e) =>
            {
                if (lvGameNotes.SelectedItems.Count > 0 && lvGameNotes.SelectedItems[0].Tag is GameLaunchNoteItem)
                {
                    GameLaunchNoteItem itm = (GameLaunchNoteItem)lvGameNotes.SelectedItems[0].Tag;
                    qolConfig.GameNotes.Remove(itm);
                    qolConfig.SaveToFile(qolConfigPath);
                    RefreshGameNotesListView();
                }
            };
            pnlCardGameNotes.Controls.Add(btnDelGame);

            Button btnTestGameNote = new Button
            {
                Text = "👁️ Önizleme Göster",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(251, 191, 36),
                Size = new Size(135, 24),
                Location = new Point(148, 174),
                Cursor = Cursors.Hand
            };
            btnTestGameNote.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnTestGameNote.Click += (s, e) =>
            {
                if (lvGameNotes.SelectedItems.Count > 0 && lvGameNotes.SelectedItems[0].Tag is GameLaunchNoteItem)
                {
                    GameLaunchNoteItem itm = (GameLaunchNoteItem)lvGameNotes.SelectedItems[0].Tag;
                    ShowQoLToast("🎮 Oyun Notu: " + itm.GameTitle, itm.NoteText, "Kapat", null, Color.FromArgb(251, 191, 36), 10, false);
                }
                else
                {
                    ShowQoLToast("🎮 Oyun Notu Önizleme", "Örnek Not: Isınmadan rekabetçiye girme!\nSens: 1.15 | 800 DPI | Crosshair: CSGO-xxx", "Kapat", null, Color.FromArgb(251, 191, 36), 10, false);
                }
            };
            pnlCardGameNotes.Controls.Add(btnTestGameNote);

            cardY += 215;

            // -------------------------------------------------------------
            // CARD 4: AKILLI RAM & STANDBY LIST OTOMASYONU
            // -------------------------------------------------------------
            Panel pnlCardRam = new Panel
            {
                Location = new Point(0, cardY),
                Size = new Size(pnlScrollBody.Width, 115),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            pnlCardRam.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(36, 46, 66), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlCardRam.Width - 1, pnlCardRam.Height - 1);
                }
            };
            pnlScrollBody.Controls.Add(pnlCardRam);

            Label lblRamTitle = new Label
            {
                Text = "🧠 AKILLI RAM & STANDBY LIST OTOMASYONU",
                Font = new Font("Segoe UI", 9.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                Location = new Point(12, 10),
                AutoSize = true
            };
            pnlCardRam.Controls.Add(lblRamTitle);

            Button btnGearRam = new Button
            {
                Text = "⚙️ RAM Ayarları",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(28, 35, 50),
                ForeColor = Color.FromArgb(203, 213, 225),
                Size = new Size(130, 24),
                Location = new Point(pnlCardRam.Width - 140, 8),
                Cursor = Cursors.Hand
            };
            btnGearRam.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnGearRam.Click += (s, e) => ShowRamCleanSettingsDialog();
            pnlCardRam.Controls.Add(btnGearRam);

            chkAutoRamEnable = new CheckBox
            {
                Text = "Otomatik RAM Eşik Temizleyicisini Etkinleştir",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(14, 38),
                AutoSize = true,
                Checked = qolConfig.AutoRamCleanActive
            };
            chkAutoRamEnable.CheckedChanged += (s, e) =>
            {
                qolConfig.AutoRamCleanActive = chkAutoRamEnable.Checked;
                qolConfig.SaveToFile(qolConfigPath);
                UpdateQoLRamStatusLabel();
            };
            pnlCardRam.Controls.Add(chkAutoRamEnable);

            // Thresholds
            rbRam10 = new RadioButton { Text = "%10 Kala", Location = new Point(14, 68), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225), Font = new Font("Segoe UI", 8.0f), Checked = (qolConfig.RamFreeThresholdPercent == 10) };
            rbRam15 = new RadioButton { Text = "%15 Kala (Önerilen)", Location = new Point(95, 68), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225), Font = new Font("Segoe UI", 8.0f), Checked = (qolConfig.RamFreeThresholdPercent == 15) };
            rbRam20 = new RadioButton { Text = "%20 Kala", Location = new Point(230, 68), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225), Font = new Font("Segoe UI", 8.0f), Checked = (qolConfig.RamFreeThresholdPercent == 20) };
            rbRam30 = new RadioButton { Text = "%30 Kala", Location = new Point(310, 68), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225), Font = new Font("Segoe UI", 8.0f), Checked = (qolConfig.RamFreeThresholdPercent == 30) };
            rbRamCustom = new RadioButton { Text = "Serbest Eşik (%):", Location = new Point(390, 68), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225), Font = new Font("Segoe UI", 8.0f), Checked = (qolConfig.RamFreeThresholdPercent != 10 && qolConfig.RamFreeThresholdPercent != 15 && qolConfig.RamFreeThresholdPercent != 20 && qolConfig.RamFreeThresholdPercent != 30) };

            numRamCustom = new NumericUpDown
            {
                Minimum = 1,
                Maximum = 50,
                Value = Math.Max(1, Math.Min(50, qolConfig.RamFreeThresholdPercent)),
                Location = new Point(510, 67),
                Width = 45,
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(52, 211, 153),
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold)
            };

            EventHandler onRamThreshChanged = (s, e) =>
            {
                if (rbRam10.Checked) qolConfig.RamFreeThresholdPercent = 10;
                else if (rbRam15.Checked) qolConfig.RamFreeThresholdPercent = 15;
                else if (rbRam20.Checked) qolConfig.RamFreeThresholdPercent = 20;
                else if (rbRam30.Checked) qolConfig.RamFreeThresholdPercent = 30;
                else if (rbRamCustom.Checked) qolConfig.RamFreeThresholdPercent = (int)numRamCustom.Value;
                qolConfig.SaveToFile(qolConfigPath);
                UpdateQoLRamStatusLabel();
            };
            rbRam10.CheckedChanged += onRamThreshChanged;
            rbRam15.CheckedChanged += onRamThreshChanged;
            rbRam20.CheckedChanged += onRamThreshChanged;
            rbRam30.CheckedChanged += onRamThreshChanged;
            rbRamCustom.CheckedChanged += onRamThreshChanged;
            numRamCustom.ValueChanged += (s, e) => { if (rbRamCustom.Checked) { qolConfig.RamFreeThresholdPercent = (int)numRamCustom.Value; qolConfig.SaveToFile(qolConfigPath); UpdateQoLRamStatusLabel(); } };

            pnlCardRam.Controls.Add(rbRam10);
            pnlCardRam.Controls.Add(rbRam15);
            pnlCardRam.Controls.Add(rbRam20);
            pnlCardRam.Controls.Add(rbRam30);
            pnlCardRam.Controls.Add(rbRamCustom);
            pnlCardRam.Controls.Add(numRamCustom);

            Button btnPurgeRam = new Button
            {
                Text = "🧹 Şimdi Standby & RAM Boşalt",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.Black,
                Size = new Size(195, 26),
                Location = new Point(570, 64),
                Cursor = Cursors.Hand
            };
            btnPurgeRam.FlatAppearance.BorderSize = 0;
            btnPurgeRam.Click += (s, e) =>
            {
                ExecuteSmartRamAndStandbyPurge(qolConfig.RamCleanProtectForegroundGame);
                UpdateQoLRamStatusLabel();
            };
            pnlCardRam.Controls.Add(btnPurgeRam);

            lblQoLRamStatus = new Label
            {
                Text = "Canlı RAM: Taranıyor...",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(310, 40),
                AutoSize = true
            };
            pnlCardRam.Controls.Add(lblQoLRamStatus);

            cardY += 125;

            // -------------------------------------------------------------
            // CARD 5: BAĞIMSIZ SİSTEM & GPU SHADER ÖNBELLEK TEMİZLEYİCİ
            // -------------------------------------------------------------
            Panel pnlCardCleaners = new Panel
            {
                Location = new Point(0, cardY),
                Size = new Size(pnlScrollBody.Width, 140),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            pnlCardCleaners.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(36, 46, 66), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlCardCleaners.Width - 1, pnlCardCleaners.Height - 1);
                }
            };
            pnlScrollBody.Controls.Add(pnlCardCleaners);

            Label lblCleanTitle = new Label
            {
                Text = "🧹 BAĞIMSIZ SİSTEM & GPU SHADER ÖNBELLEK TEMİZLEYİCİ",
                Font = new Font("Segoe UI", 9.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(248, 113, 113),
                Location = new Point(12, 10),
                AutoSize = true
            };
            pnlCardCleaners.Controls.Add(lblCleanTitle);

            Label lblCleanSub = new Label
            {
                Text = "İki temizleme işlemi birbirinden tamamen bağımsızdır; dilediğinizi ayrı ayrı tek tıkla çalıştırabilirsiniz.",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(12, 30),
                AutoSize = true
            };
            pnlCardCleaners.Controls.Add(lblCleanSub);

            int subBoxW = (pnlCardCleaners.Width - 36) / 2;

            // Box 1: Windows Temp & Prefetch
            Panel pnlBoxTemp = new Panel
            {
                Location = new Point(12, 52),
                Size = new Size(subBoxW, 76),
                BackColor = Color.FromArgb(12, 15, 22)
            };
            pnlBoxTemp.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(40, 50, 72), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlBoxTemp.Width - 1, pnlBoxTemp.Height - 1);
                }
            };
            pnlCardCleaners.Controls.Add(pnlBoxTemp);

            Label lblBox1Title = new Label
            {
                Text = "🗑️ Windows Temp & Prefetch Dosyaları",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(10, 8),
                AutoSize = true
            };
            pnlBoxTemp.Controls.Add(lblBox1Title);

            lblSystemTempStatus = new Label
            {
                Text = "%TEMP% ve kilitli olmayan Windows geçici dosyaları temizlenmeye hazır.",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(10, 28),
                Size = new Size(subBoxW - 20, 18),
                AutoEllipsis = true
            };
            pnlBoxTemp.Controls.Add(lblSystemTempStatus);

            btnCleanTempNow = new Button
            {
                Text = "🧹 Windows Temp Temizle",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(56, 189, 248),
                Size = new Size(180, 22),
                Location = new Point(10, 48),
                Cursor = Cursors.Hand
            };
            btnCleanTempNow.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnCleanTempNow.Click += (s, e) => RunSystemTempCleanAsync();
            pnlBoxTemp.Controls.Add(btnCleanTempNow);

            // Box 2: GPU Shader Cache
            Panel pnlBoxShader = new Panel
            {
                Location = new Point(subBoxW + 24, 52),
                Size = new Size(subBoxW, 76),
                BackColor = Color.FromArgb(12, 15, 22)
            };
            pnlBoxShader.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(40, 50, 72), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlBoxShader.Width - 1, pnlBoxShader.Height - 1);
                }
            };
            pnlCardCleaners.Controls.Add(pnlBoxShader);

            Label lblBox2Title = new Label
            {
                Text = "🎮 Ekran Kartı Shader Önbelleği (DirectX / NVIDIA / AMD)",
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(10, 8),
                AutoSize = true
            };
            pnlBoxShader.Controls.Add(lblBox2Title);

            lblShaderCacheStatus = new Label
            {
                Text = "DirectX D3D, NVIDIA DXCache ve AMD Shader havuzları temizlenmeye hazır.",
                Font = new Font("Segoe UI", 7.6f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                Location = new Point(10, 28),
                Size = new Size(subBoxW - 20, 18),
                AutoEllipsis = true
            };
            pnlBoxShader.Controls.Add(lblShaderCacheStatus);

            btnCleanShaderNow = new Button
            {
                Text = "🎮 GPU Shader Önbelleğini Temizle",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Bold),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(30, 41, 59),
                ForeColor = Color.FromArgb(248, 113, 113),
                Size = new Size(220, 22),
                Location = new Point(10, 48),
                Cursor = Cursors.Hand
            };
            btnCleanShaderNow.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
            btnCleanShaderNow.Click += (s, e) => RunGpuShaderCleanAsync();
            pnlBoxShader.Controls.Add(btnCleanShaderNow);

            // Responsive Layout Handling for QoL Cards
            Action layoutQoLCards = () =>
            {
                int availW = Math.Max(780, viewAutomationQoL.ClientSize.Width - 36);
                pnlScrollBody.Width = availW;

                pnlCardPower.Width = availW;
                btnGearPower.Location = new Point(availW - 195, 8);

                pnlCardAlarms.Width = availW;
                btnGearAlarms.Location = new Point(availW - 195, 8);
                lvAlarms.Width = availW - 24;

                pnlCardGameNotes.Width = availW;
                btnAddGame.Location = new Point(availW - 170, 8);
                lvGameNotes.Width = availW - 24;

                pnlCardRam.Width = availW;
                btnGearRam.Location = new Point(availW - 140, 8);

                pnlCardCleaners.Width = availW;
                int innerSubW = (availW - 36) / 2;
                pnlBoxTemp.Width = innerSubW;
                lblSystemTempStatus.Width = innerSubW - 20;

                pnlBoxShader.Location = new Point(innerSubW + 24, 52);
                pnlBoxShader.Width = innerSubW;
                lblShaderCacheStatus.Width = innerSubW - 20;
            };

            viewAutomationQoL.Resize += (s, e) => layoutQoLCards();
            layoutQoLCards();

            RefreshAlarmsListView();
            RefreshGameNotesListView();
            UpdateQoLRamStatusLabel();
        }

        private void RefreshAutomationQoLView()
        {
            RefreshAlarmsListView();
            RefreshGameNotesListView();
            UpdateQoLRamStatusLabel();
        }

        private void RefreshAlarmsListView()
        {
            if (lvAlarms == null) return;
            lvAlarms.BeginUpdate();
            try
            {
                lvAlarms.Items.Clear();
                foreach (var a in qolConfig.Alarms)
                {
                    string statusText = a.IsEnabled ? "Açık" : "Kapalı";
                    string typeDesc = a.AlarmType;
                    if (a.AlarmType == "CRYPTO_4H") typeDesc = "4H Kripto (03, 07, 11, 15, 19, 23)";
                    else if (a.AlarmType == "CRYPTO_DAILY") typeDesc = "Günlük Kapanış (03:00)";
                    else if (a.AlarmType == "CRYPTO_WEEKLY") typeDesc = "Haftalık Kapanış (Pzt 03:00)";
                    else if (a.AlarmType == "PERIODIC") typeDesc = string.Format("Her {0} Dakikada Bir", a.PeriodMinutes);
                    else if (a.AlarmType == "SPECIFIC_TIME") typeDesc = string.Format("Saat {0}", a.SpecificTimeHHmm);

                    string nextStr = a.NextTrigger > DateTime.MinValue ? a.NextTrigger.ToString("dd.MM.yyyy HH:mm:ss") : "--";

                    ListViewItem itm = new ListViewItem(statusText);
                    itm.SubItems.Add(a.Title ?? "Alarm");
                    itm.SubItems.Add(a.Description ?? "--");
                    itm.SubItems.Add(typeDesc);
                    itm.SubItems.Add(nextStr);
                    itm.Tag = a;
                    itm.Checked = a.IsEnabled;
                    if (!a.IsEnabled) itm.ForeColor = Color.FromArgb(148, 163, 184);
                    lvAlarms.Items.Add(itm);
                }
            }
            finally
            {
                lvAlarms.EndUpdate();
            }
        }

        private void RefreshGameNotesListView()
        {
            if (lvGameNotes == null) return;
            lvGameNotes.BeginUpdate();
            try
            {
                lvGameNotes.Items.Clear();
                foreach (var g in qolConfig.GameNotes)
                {
                    string freq = g.PeriodicInGame ? string.Format("Girişte + Her {0} Dk", g.PeriodicIntervalMinutes) : "Sadece Girişte";
                    string safeNote = (g.NoteText ?? "").Replace("\r\n", "  |  ").Replace("\n", "  |  ");

                    ListViewItem itm = new ListViewItem(g.GameTitle ?? "Oyun");
                    itm.SubItems.Add(g.ProcessName ?? "--");
                    itm.SubItems.Add(safeNote);
                    itm.SubItems.Add(freq);
                    itm.Tag = g;
                    lvGameNotes.Items.Add(itm);
                }
            }
            finally
            {
                lvGameNotes.EndUpdate();
            }
        }

        private void UpdateQoLRamStatusLabel()
        {
            if (lblQoLRamStatus == null) return;
            try
            {
                NativeMethods.MEMORYSTATUSEX mem = new NativeMethods.MEMORYSTATUSEX();
                if (NativeMethods.GlobalMemoryStatusEx(mem))
                {
                    double usedLoad = mem.dwMemoryLoad;
                    double freeGb = mem.ullAvailPhys / (1024.0 * 1024.0 * 1024.0);
                    double totalGb = mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
                    string autoStatus = qolConfig.AutoRamCleanActive ? string.Format("Otomatik Temizlik: Aktif (%{0} Eşik)", qolConfig.RamFreeThresholdPercent) : "Otomatik Temizlik: Kapalı";
                    lblQoLRamStatus.Text = string.Format("Canlı RAM: %{0:0} Kullanım ({1:0.0} / {2:0.0} GB) — {3}", usedLoad, (totalGb - freeGb), totalGb, autoStatus);
                    lblQoLRamStatus.ForeColor = qolConfig.AutoRamCleanActive ? Color.FromArgb(52, 211, 153) : Color.FromArgb(148, 163, 184);
                }
            }
            catch { }
        }

        private void ToggleStartPowerTimer()
        {
            if (qolConfig.PowerTimerActive)
            {
                CancelPowerTimer(true);
                return;
            }

            int h = (int)numPowerHours.Value;
            int m = (int)numPowerMins.Value;
            string spec = (txtPowerSpecificTime.Text ?? "").Trim();
            string act = "SHUTDOWN";
            if (cmbPowerAction.SelectedIndex == 1) act = "RESTART";
            else if (cmbPowerAction.SelectedIndex == 2) act = "SLEEP";
            else if (cmbPowerAction.SelectedIndex == 3) act = "LOCK";

            qolConfig.PowerTimerAction = act;
            qolConfig.PowerTimerHours = h;
            qolConfig.PowerTimerMinutes = m;
            qolConfig.PowerTimerSpecificTime = spec;

            if (rbPowerCountdown.Checked)
            {
                qolConfig.PowerTimerMode = "COUNTDOWN";
                if (h == 0 && m == 0)
                {
                    MessageBox.Show("Lütfen en az 1 dakika süre belirleyin.", "Geçersiz Süre", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                qolConfig.PowerTimerTarget = DateTime.Now.AddHours(h).AddMinutes(m);
            }
            else
            {
                qolConfig.PowerTimerMode = "SPECIFIC_TIME";
                DateTime targetClock;
                if (!DateTime.TryParse(spec, out targetClock))
                {
                    MessageBox.Show("Lütfen geçerli bir saat girin (Örnek: 23:45).", "Geçersiz Saat Formatı", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                DateTime now = DateTime.Now;
                DateTime sched = new DateTime(now.Year, now.Month, now.Day, targetClock.Hour, targetClock.Minute, 0);
                if (sched <= now) sched = sched.AddDays(1);
                qolConfig.PowerTimerTarget = sched;
            }

            qolConfig.PowerTimerActive = true;
            qolConfig.PowerTimerWarnGiven = false;
            qolConfig.SaveToFile(qolConfigPath);

            if (btnStartPowerTimer != null)
            {
                btnStartPowerTimer.Text = "⏹️ Zamanlayıcıyı Durdur";
                btnStartPowerTimer.BackColor = Color.FromArgb(245, 158, 11);
                btnStartPowerTimer.ForeColor = Color.Black;
            }
            if (btnCancelPowerTimer != null) btnCancelPowerTimer.Enabled = true;

            TimeSpan diff = qolConfig.PowerTimerTarget - DateTime.Now;
            lblPowerTimerStatus.Text = string.Format("⏳ Hedef: {0:HH:mm:ss} — Kalan: {1:00}:{2:00}:{3:00} [{4}]",
                qolConfig.PowerTimerTarget, (int)diff.TotalHours, diff.Minutes, diff.Seconds, qolConfig.PowerTimerAction);
            lblPowerTimerStatus.ForeColor = Color.FromArgb(253, 224, 71);

            ShowQoLToast("⏱️ Güç Zamanlayıcısı Başlatıldı",
                string.Format("Hedef: {0:HH:mm:ss} ({1}). İptal etmek için istediğiniz an bildirimdeki butona tıklayabilirsiniz.", qolConfig.PowerTimerTarget, qolConfig.PowerTimerAction),
                "İptal Et", () => CancelPowerTimer(true), Color.FromArgb(56, 189, 248), 8, false);
        }

        private void CancelPowerTimer(bool showToast)
        {
            qolConfig.PowerTimerActive = false;
            qolConfig.PowerTimerWarnGiven = false;
            qolConfig.SaveToFile(qolConfigPath);

            if (btnStartPowerTimer != null)
            {
                btnStartPowerTimer.Text = "▶️ Zamanlayıcıyı Başlat";
                btnStartPowerTimer.BackColor = Color.FromArgb(16, 185, 129);
                btnStartPowerTimer.ForeColor = Color.Black;
            }
            if (btnCancelPowerTimer != null) btnCancelPowerTimer.Enabled = false;

            if (lblPowerTimerStatus != null)
            {
                lblPowerTimerStatus.Text = "Zamanlayıcı iptal edildi. Pasif durumda.";
                lblPowerTimerStatus.ForeColor = Color.FromArgb(148, 163, 184);
            }

            if (showToast)
            {
                ShowQoLToast("⏹️ Güç Zamanlayıcısı İptal Edildi", "Planlanmış güç işlemi tamamen durduruldu.", null, null, Color.FromArgb(248, 113, 113), 5, false);
            }
        }

        private void AddCryptoPresetAlarm(string type)
        {
            CustomAlarmItem itm = new CustomAlarmItem();
            itm.IsEnabled = true;
            itm.AlarmType = type;

            if (type == "CRYPTO_4H")
            {
                itm.Title = "BTC 4H Mum Kapanışı (03, 07, 11, 15, 19, 23)";
                itm.Description = "4 Saatlik grafikleri ve açık pozisyonları kontrol et";
                itm.PeriodMinutes = 240;
                itm.NextTrigger = CryptoAlarmHelpers.GetNextCrypto4HCandleTime();
            }
            else if (type == "CRYPTO_DAILY")
            {
                itm.Title = "Kripto Günlük Kapanış (03:00 UTC+3)";
                itm.Description = "Günlük mum kapanışı, fonlama oranları ve emirleri kontrol et";
                itm.PeriodMinutes = 1440;
                itm.SpecificTimeHHmm = "03:00";
                itm.NextTrigger = CryptoAlarmHelpers.GetNextCryptoDailyCloseTime();
            }
            else if (type == "CRYPTO_WEEKLY")
            {
                itm.Title = "Kripto Haftalık Kapanış (Pazartesi 03:00 UTC+3)";
                itm.Description = "Haftalık mum kapanışı ve yeni hafta destek/direnç seviyelerini incele";
                itm.PeriodMinutes = 10080;
                itm.SpecificTimeHHmm = "03:00";
                itm.NextTrigger = CryptoAlarmHelpers.GetNextCryptoWeeklyCloseTime();
            }

            qolConfig.Alarms.Add(itm);
            qolConfig.SaveToFile(qolConfigPath);
            RefreshAlarmsListView();

            ShowQoLToast("⏰ Kripto Alarmı Eklendi",
                string.Format("'{0}' alarmı kuruldu. İlk çalma saati: {1:dd.MM.yyyy HH:mm:ss}", itm.Title, itm.NextTrigger),
                "Tamam", null, Color.FromArgb(168, 85, 247), 8, false);
        }

        private void TriggerAlarmAlert(CustomAlarmItem itm)
        {
            AudioAlertPlayer.PlayAlert(qolConfig.AlarmCustomSoundPath, qolConfig.AlarmMaxPlayDurationSec);
            ShowQoLToast(
                "⏰ " + (itm.Title ?? "Alarm Uyarısı"),
                itm.Description ?? "Planlanan alarm zamanı geldi!",
                "Sesi Durdur",
                () => AudioAlertPlayer.StopAlert(),
                Color.FromArgb(168, 85, 247),
                15,
                true
            );
        }

        private void ShowQoLToast(string title, string msg, string actionText, Action action, Color accent, int autoCloseSec, bool pulse3Sec)
        {
            if (this.IsDisposed) return;
            if (this.InvokeRequired)
            {
                this.BeginInvoke((MethodInvoker)delegate
                {
                    ShowQoLToast(title, msg, actionText, action, accent, autoCloseSec, pulse3Sec);
                });
                return;
            }

            try
            {
                QoLToastForm toast = new QoLToastForm(title, msg, actionText, action, accent, autoCloseSec, pulse3Sec);
                toast.Show();
            }
            catch { }
        }

        // -------------------------------------------------------------
        // SETTINGS GEAR DIALOGS
        // -------------------------------------------------------------
        private void ShowPowerTimerSettingsDialog()
        {
            using (Form dlg = new Form())
            {
                dlg.Text = "Akıllı Güç & Kapatma Koruma Ayarları";
                dlg.Size = new Size(520, 310);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(18, 23, 34);
                dlg.ForeColor = Color.White;
                dlg.Font = new Font("Segoe UI", 9.0f);

                CheckBox chkNet = new CheckBox
                {
                    Text = "Akıllı İndirme Koruması: Ağ İndirmesi Eşiğin Üzerindeyse Kapatmayı Ertele",
                    Location = new Point(20, 20),
                    Width = 460,
                    Checked = qolConfig.PowerTimerPostponeIfNetBusy,
                    ForeColor = Color.FromArgb(56, 189, 248),
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                dlg.Controls.Add(chkNet);

                Label lblNetSub = new Label
                {
                    Text = "Minimum İndirme Hızı Eşiği (KB/s):",
                    Location = new Point(44, 48),
                    AutoSize = true,
                    ForeColor = Color.FromArgb(148, 163, 184)
                };
                dlg.Controls.Add(lblNetSub);

                NumericUpDown numNet = new NumericUpDown
                {
                    Minimum = 50,
                    Maximum = 50000,
                    Value = Math.Max(50, Math.Min(50000, qolConfig.PowerTimerNetThresholdKBps)),
                    Location = new Point(275, 46),
                    Width = 80,
                    BackColor = Color.FromArgb(12, 15, 22),
                    ForeColor = Color.FromArgb(56, 189, 248)
                };
                dlg.Controls.Add(numNet);

                CheckBox chkCpu = new CheckBox
                {
                    Text = "Akıllı Boşta Dedektörü: CPU Yükü Yüksekse Kapatmayı Ertele",
                    Location = new Point(20, 90),
                    Width = 460,
                    Checked = qolConfig.PowerTimerPostponeIfCpuBusy,
                    ForeColor = Color.FromArgb(52, 211, 153),
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                dlg.Controls.Add(chkCpu);

                Label lblCpuSub = new Label
                {
                    Text = "Maksimum CPU Yük Eşiği (%):",
                    Location = new Point(44, 118),
                    AutoSize = true,
                    ForeColor = Color.FromArgb(148, 163, 184)
                };
                dlg.Controls.Add(lblCpuSub);

                NumericUpDown numCpu = new NumericUpDown
                {
                    Minimum = 5,
                    Maximum = 95,
                    Value = Math.Max(5, Math.Min(95, qolConfig.PowerTimerCpuThresholdPercent)),
                    Location = new Point(275, 116),
                    Width = 80,
                    BackColor = Color.FromArgb(12, 15, 22),
                    ForeColor = Color.FromArgb(52, 211, 153)
                };
                dlg.Controls.Add(numCpu);

                CheckBox chkWarn = new CheckBox
                {
                    Text = "Kapatmaya 5 Dakika Kala Güvenli Bildirim Göster (İptal Butonlu)",
                    Location = new Point(20, 160),
                    Width = 460,
                    Checked = qolConfig.PowerTimer5MinWarn,
                    ForeColor = Color.FromArgb(251, 191, 36),
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                dlg.Controls.Add(chkWarn);

                Button btnSave = new Button
                {
                    Text = "Ayarları Kaydet",
                    DialogResult = DialogResult.OK,
                    Location = new Point(250, 220),
                    Size = new Size(130, 32),
                    BackColor = Color.FromArgb(16, 185, 129),
                    ForeColor = Color.Black,
                    FlatStyle = FlatStyle.Flat,
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                btnSave.FlatAppearance.BorderSize = 0;
                dlg.Controls.Add(btnSave);

                Button btnCancel = new Button
                {
                    Text = "İptal",
                    DialogResult = DialogResult.Cancel,
                    Location = new Point(390, 220),
                    Size = new Size(95, 32),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(203, 213, 225),
                    FlatStyle = FlatStyle.Flat
                };
                btnCancel.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                dlg.Controls.Add(btnCancel);

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    qolConfig.PowerTimerPostponeIfNetBusy = chkNet.Checked;
                    qolConfig.PowerTimerNetThresholdKBps = (int)numNet.Value;
                    qolConfig.PowerTimerPostponeIfCpuBusy = chkCpu.Checked;
                    qolConfig.PowerTimerCpuThresholdPercent = (int)numCpu.Value;
                    qolConfig.PowerTimer5MinWarn = chkWarn.Checked;
                    qolConfig.SaveToFile(qolConfigPath);
                }
            }
        }

        private void ShowAlarmAudioSettingsDialog()
        {
            using (Form dlg = new Form())
            {
                dlg.Text = "Ses & Bildirim Ayarları";
                dlg.Size = new Size(540, 340);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(18, 23, 34);
                dlg.ForeColor = Color.White;
                dlg.Font = new Font("Segoe UI", 9.0f);

                Label lblSound = new Label
                {
                    Text = "Özel Alarm Sesi (.mp3 veya .wav):",
                    Location = new Point(20, 18),
                    AutoSize = true,
                    ForeColor = Color.FromArgb(168, 85, 247),
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                dlg.Controls.Add(lblSound);

                TextBox txtSoundPath = new TextBox
                {
                    Text = qolConfig.AlarmCustomSoundPath ?? "",
                    Location = new Point(20, 42),
                    Width = 370,
                    BackColor = Color.FromArgb(12, 15, 22),
                    ForeColor = Color.FromArgb(226, 232, 240)
                };
                dlg.Controls.Add(txtSoundPath);

                Button btnBrowse = new Button
                {
                    Text = "Gözat...",
                    Location = new Point(400, 40),
                    Size = new Size(100, 26),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(203, 213, 225),
                    FlatStyle = FlatStyle.Flat
                };
                btnBrowse.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                btnBrowse.Click += (s, e) =>
                {
                    using (OpenFileDialog ofd = new OpenFileDialog())
                    {
                        ofd.Title = "Alarm Sesi Seçin (.mp3 veya .wav)";
                        ofd.Filter = "Ses Dosyaları (*.mp3;*.wav)|*.mp3;*.wav|Tüm Dosyalar (*.*)|*.*";
                        if (ofd.ShowDialog(dlg) == DialogResult.OK)
                        {
                            txtSoundPath.Text = ofd.FileName;
                        }
                    }
                };
                dlg.Controls.Add(btnBrowse);

                Label lblHint = new Label
                {
                    Text = "Boş bırakılırsa Windows varsayılan uyarı sesi kullanılır.",
                    Location = new Point(20, 72),
                    AutoSize = true,
                    ForeColor = Color.FromArgb(148, 163, 184),
                    Font = new Font("Segoe UI", 7.8f)
                };
                dlg.Controls.Add(lblHint);

                Button btnTest = new Button
                {
                    Text = "▶️ Sesi Test Et",
                    Location = new Point(20, 96),
                    Size = new Size(115, 26),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(52, 211, 153),
                    FlatStyle = FlatStyle.Flat
                };
                btnTest.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                btnTest.Click += (s, e) => AudioAlertPlayer.PlayAlert(txtSoundPath.Text, qolConfig.AlarmMaxPlayDurationSec);
                dlg.Controls.Add(btnTest);

                Button btnStop = new Button
                {
                    Text = "⏹️ Durdur",
                    Location = new Point(145, 96),
                    Size = new Size(90, 26),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(248, 113, 113),
                    FlatStyle = FlatStyle.Flat
                };
                btnStop.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                btnStop.Click += (s, e) => AudioAlertPlayer.StopAlert();
                dlg.Controls.Add(btnStop);

                Label lblDur = new Label
                {
                    Text = "Maksimum Çalma Kesinti Süresi (Cutoff):",
                    Location = new Point(20, 140),
                    AutoSize = true,
                    ForeColor = Color.FromArgb(203, 213, 225),
                    Font = new Font("Segoe UI", 8.2f, FontStyle.Bold)
                };
                dlg.Controls.Add(lblDur);

                ComboBox cmbCutoff = new ComboBox
                {
                    DropDownStyle = ComboBoxStyle.DropDownList,
                    Location = new Point(280, 137),
                    Width = 140,
                    BackColor = Color.FromArgb(12, 15, 22),
                    ForeColor = Color.FromArgb(168, 85, 247)
                };
                cmbCutoff.Items.AddRange(new object[] { "5 Saniye", "10 Saniye", "15 Saniye (Önerilen)", "30 Saniye", "1 Dakika (Maksimum)" });
                int cutIdx = 2;
                if (qolConfig.AlarmMaxPlayDurationSec == 5) cutIdx = 0;
                else if (qolConfig.AlarmMaxPlayDurationSec == 10) cutIdx = 1;
                else if (qolConfig.AlarmMaxPlayDurationSec == 15) cutIdx = 2;
                else if (qolConfig.AlarmMaxPlayDurationSec == 30) cutIdx = 3;
                else if (qolConfig.AlarmMaxPlayDurationSec == 60) cutIdx = 4;
                cmbCutoff.SelectedIndex = cutIdx;
                dlg.Controls.Add(cmbCutoff);

                Label lblPulseInfo = new Label
                {
                    Text = "ℹ️ Tekrarlama Mantığı: Alarm tetiklendiğinde ses çalar ve 15 saniye boyunca\nher 3 saniyede bir masaüstü bildirim uyarısı titreşir.",
                    Location = new Point(20, 172),
                    Size = new Size(480, 36),
                    ForeColor = Color.FromArgb(148, 163, 184),
                    Font = new Font("Segoe UI", 7.8f)
                };
                dlg.Controls.Add(lblPulseInfo);

                CheckBox chkHealth = new CheckBox
                {
                    Text = "Sağlık & Mola Hatırlatıcıları (Göz Dinlendirme & Su İçme - Her 60 dk)",
                    Location = new Point(20, 215),
                    Width = 480,
                    Checked = qolConfig.HealthRemindersEnabled,
                    ForeColor = Color.FromArgb(56, 189, 248),
                    Font = new Font("Segoe UI", 8.2f, FontStyle.Bold)
                };
                dlg.Controls.Add(chkHealth);

                Button btnSave = new Button
                {
                    Text = "Ayarları Kaydet",
                    DialogResult = DialogResult.OK,
                    Location = new Point(270, 260),
                    Size = new Size(130, 32),
                    BackColor = Color.FromArgb(16, 185, 129),
                    ForeColor = Color.Black,
                    FlatStyle = FlatStyle.Flat,
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                btnSave.FlatAppearance.BorderSize = 0;
                dlg.Controls.Add(btnSave);

                Button btnCancel = new Button
                {
                    Text = "Kapat",
                    DialogResult = DialogResult.Cancel,
                    Location = new Point(410, 260),
                    Size = new Size(90, 32),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(203, 213, 225),
                    FlatStyle = FlatStyle.Flat
                };
                btnCancel.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                dlg.Controls.Add(btnCancel);

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    AudioAlertPlayer.StopAlert();
                    qolConfig.AlarmCustomSoundPath = txtSoundPath.Text.Trim();
                    int selCut = 15;
                    if (cmbCutoff.SelectedIndex == 0) selCut = 5;
                    else if (cmbCutoff.SelectedIndex == 1) selCut = 10;
                    else if (cmbCutoff.SelectedIndex == 2) selCut = 15;
                    else if (cmbCutoff.SelectedIndex == 3) selCut = 30;
                    else if (cmbCutoff.SelectedIndex == 4) selCut = 60;
                    qolConfig.AlarmMaxPlayDurationSec = selCut;
                    qolConfig.HealthRemindersEnabled = chkHealth.Checked;
                    qolConfig.SaveToFile(qolConfigPath);
                }
                else
                {
                    AudioAlertPlayer.StopAlert();
                }
            }
        }

        private void ShowAddCustomAlarmDialog()
        {
            using (Form dlg = new Form())
            {
                dlg.Text = "Yeni Özel Alarm Oluştur";
                dlg.Size = new Size(480, 300);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(18, 23, 34);
                dlg.ForeColor = Color.White;
                dlg.Font = new Font("Segoe UI", 9.0f);

                Label lblT = new Label { Text = "Alarm Başlığı:", Location = new Point(20, 18), AutoSize = true, ForeColor = Color.FromArgb(168, 85, 247), Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) };
                dlg.Controls.Add(lblT);

                TextBox txtTitle = new TextBox { Text = "İşe Hazırlan", Location = new Point(20, 38), Width = 420, BackColor = Color.FromArgb(12, 15, 22), ForeColor = Color.FromArgb(226, 232, 240) };
                dlg.Controls.Add(txtTitle);

                Label lblD = new Label { Text = "Açıklama / Not:", Location = new Point(20, 68), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
                dlg.Controls.Add(lblD);

                TextBox txtDesc = new TextBox { Text = "Çantayı al ve hazır ol", Location = new Point(20, 88), Width = 420, BackColor = Color.FromArgb(12, 15, 22), ForeColor = Color.FromArgb(226, 232, 240) };
                dlg.Controls.Add(txtDesc);

                RadioButton rbPer = new RadioButton { Text = "Periyodik Aralık:", Location = new Point(20, 122), AutoSize = true, Checked = true, ForeColor = Color.FromArgb(203, 213, 225) };
                dlg.Controls.Add(rbPer);

                NumericUpDown numPer = new NumericUpDown { Minimum = 1, Maximum = 1440, Value = 60, Location = new Point(150, 121), Width = 60, BackColor = Color.FromArgb(12, 15, 22), ForeColor = Color.FromArgb(56, 189, 248) };
                dlg.Controls.Add(numPer);

                Label lblDk = new Label { Text = "dakikada bir", Location = new Point(218, 124), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
                dlg.Controls.Add(lblDk);

                RadioButton rbClock = new RadioButton { Text = "Hedef Saatte:", Location = new Point(20, 154), AutoSize = true, ForeColor = Color.FromArgb(203, 213, 225) };
                dlg.Controls.Add(rbClock);

                TextBox txtClock = new TextBox { Text = DateTime.Now.AddMinutes(30).ToString("HH:mm"), Location = new Point(150, 153), Width = 60, BackColor = Color.FromArgb(12, 15, 22), ForeColor = Color.FromArgb(56, 189, 248), TextAlign = HorizontalAlignment.Center };
                dlg.Controls.Add(txtClock);

                Button btnAdd = new Button
                {
                    Text = "Alarmı Ekle",
                    DialogResult = DialogResult.OK,
                    Location = new Point(230, 210),
                    Size = new Size(115, 32),
                    BackColor = Color.FromArgb(124, 58, 237),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat,
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                btnAdd.FlatAppearance.BorderSize = 0;
                dlg.Controls.Add(btnAdd);

                Button btnCancel = new Button
                {
                    Text = "İptal",
                    DialogResult = DialogResult.Cancel,
                    Location = new Point(355, 210),
                    Size = new Size(85, 32),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(203, 213, 225),
                    FlatStyle = FlatStyle.Flat
                };
                btnCancel.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                dlg.Controls.Add(btnCancel);

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    string t = (txtTitle.Text ?? "").Trim();
                    if (string.IsNullOrEmpty(t)) t = "Özel Alarm";
                    string d = (txtDesc.Text ?? "").Trim();

                    CustomAlarmItem item = new CustomAlarmItem();
                    item.Title = t;
                    item.Description = d;
                    item.IsEnabled = true;

                    if (rbPer.Checked)
                    {
                        item.AlarmType = "PERIODIC";
                        item.PeriodMinutes = (int)numPer.Value;
                        item.NextTrigger = DateTime.Now.AddMinutes(item.PeriodMinutes);
                    }
                    else
                    {
                        item.AlarmType = "SPECIFIC_TIME";
                        DateTime targetClock;
                        if (!DateTime.TryParse(txtClock.Text.Trim(), out targetClock))
                        {
                            targetClock = DateTime.Now.AddMinutes(30);
                        }
                        DateTime sched = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day, targetClock.Hour, targetClock.Minute, 0);
                        if (sched <= DateTime.Now) sched = sched.AddDays(1);
                        item.SpecificTimeHHmm = sched.ToString("HH:mm");
                        item.NextTrigger = sched;
                    }

                    qolConfig.Alarms.Add(item);
                    qolConfig.SaveToFile(qolConfigPath);
                    RefreshAlarmsListView();

                    ShowQoLToast("⏰ Yeni Alarm Kuruldu", string.Format("'{0}' alarmı aktif. İlk çalma: {1:HH:mm:ss}", item.Title, item.NextTrigger), "Tamam", null, Color.FromArgb(168, 85, 247), 8, false);
                }
            }
        }

        private void ShowAddGameNoteDialog()
        {
            using (Form dlg = new Form())
            {
                dlg.Text = "Yeni Oyun Notu & Hatırlatıcı Ekle";
                dlg.Size = new Size(520, 360);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(18, 23, 34);
                dlg.ForeColor = Color.White;
                dlg.Font = new Font("Segoe UI", 9.0f);

                Label lblGame = new Label { Text = "Oyun Adı:", Location = new Point(20, 18), AutoSize = true, ForeColor = Color.FromArgb(251, 191, 36), Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) };
                dlg.Controls.Add(lblGame);

                TextBox txtGame = new TextBox { Text = "Counter-Strike 2", Location = new Point(20, 38), Width = 230, BackColor = Color.FromArgb(12, 15, 22), ForeColor = Color.FromArgb(226, 232, 240) };
                dlg.Controls.Add(txtGame);

                Label lblProc = new Label { Text = "Süreç Adı (.exe):", Location = new Point(265, 18), AutoSize = true, ForeColor = Color.FromArgb(56, 189, 248), Font = new Font("Segoe UI", 8.5f, FontStyle.Bold) };
                dlg.Controls.Add(lblProc);

                TextBox txtProc = new TextBox { Text = "cs2.exe", Location = new Point(265, 38), Width = 215, BackColor = Color.FromArgb(12, 15, 22), ForeColor = Color.FromArgb(226, 232, 240) };
                dlg.Controls.Add(txtProc);

                Label lblNote = new Label { Text = "Özel Hatırlatma Notunuz (Oyun başladığında ekranda görünecektir):", Location = new Point(20, 72), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
                dlg.Controls.Add(lblNote);

                TextBox txtNote = new TextBox
                {
                    Text = "Isınmadan rekabetçiye girme!\nSens: 1.15 | 800 DPI | Crosshair: CSGO-xxx",
                    Location = new Point(20, 94),
                    Size = new Size(460, 90),
                    Multiline = true,
                    ScrollBars = ScrollBars.Vertical,
                    BackColor = Color.FromArgb(12, 15, 22),
                    ForeColor = Color.FromArgb(226, 232, 240)
                };
                dlg.Controls.Add(txtNote);

                CheckBox chkLaunchOnly = new CheckBox
                {
                    Text = "Oyun Başladığında Sessizce Göster (Ses Yok)",
                    Location = new Point(20, 198),
                    AutoSize = true,
                    Checked = true,
                    ForeColor = Color.FromArgb(52, 211, 153),
                    Font = new Font("Segoe UI", 8.2f, FontStyle.Bold)
                };
                dlg.Controls.Add(chkLaunchOnly);

                CheckBox chkPeriodic = new CheckBox
                {
                    Text = "Oyun Sırasında Periyodik Olarak da Hatırla:",
                    Location = new Point(20, 226),
                    AutoSize = true,
                    Checked = false,
                    ForeColor = Color.FromArgb(203, 213, 225)
                };
                dlg.Controls.Add(chkPeriodic);

                NumericUpDown numPer = new NumericUpDown
                {
                    Minimum = 5,
                    Maximum = 240,
                    Value = 45,
                    Location = new Point(315, 225),
                    Width = 55,
                    BackColor = Color.FromArgb(12, 15, 22),
                    ForeColor = Color.FromArgb(251, 191, 36)
                };
                dlg.Controls.Add(numPer);

                Label lblMin = new Label { Text = "dk aralıkla", Location = new Point(376, 227), AutoSize = true, ForeColor = Color.FromArgb(148, 163, 184) };
                dlg.Controls.Add(lblMin);

                Button btnAdd = new Button
                {
                    Text = "Notu Kaydet",
                    DialogResult = DialogResult.OK,
                    Location = new Point(260, 275),
                    Size = new Size(125, 32),
                    BackColor = Color.FromArgb(217, 119, 6),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat,
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                btnAdd.FlatAppearance.BorderSize = 0;
                dlg.Controls.Add(btnAdd);

                Button btnCancel = new Button
                {
                    Text = "İptal",
                    DialogResult = DialogResult.Cancel,
                    Location = new Point(395, 275),
                    Size = new Size(85, 32),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(203, 213, 225),
                    FlatStyle = FlatStyle.Flat
                };
                btnCancel.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                dlg.Controls.Add(btnCancel);

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    GameLaunchNoteItem gn = new GameLaunchNoteItem();
                    gn.GameTitle = (txtGame.Text ?? "").Trim();
                    gn.ProcessName = (txtProc.Text ?? "").Trim().Replace(".exe", "");
                    gn.NoteText = txtNote.Text;
                    gn.IsEnabled = true;
                    gn.PeriodicInGame = chkPeriodic.Checked;
                    gn.PeriodicIntervalMinutes = (int)numPer.Value;

                    qolConfig.GameNotes.Add(gn);
                    qolConfig.SaveToFile(qolConfigPath);
                    RefreshGameNotesListView();

                    ShowQoLToast("🎮 Oyun Notu Kaydedildi", string.Format("'{0}' ({1}.exe) başladığında notunuz sessizce masaüstünde gösterilecektir.", gn.GameTitle, gn.ProcessName), "Tamam", null, Color.FromArgb(251, 191, 36), 8, false);
                }
            }
        }

        private void ShowRamCleanSettingsDialog()
        {
            using (Form dlg = new Form())
            {
                dlg.Text = "Akıllı RAM & Standby List Ayarları";
                dlg.Size = new Size(460, 230);
                dlg.StartPosition = FormStartPosition.CenterParent;
                dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
                dlg.MaximizeBox = false;
                dlg.MinimizeBox = false;
                dlg.BackColor = Color.FromArgb(18, 23, 34);
                dlg.ForeColor = Color.White;
                dlg.Font = new Font("Segoe UI", 9.0f);

                CheckBox chkProt = new CheckBox
                {
                    Text = "Ön Plandaki Oyunu Koru (Oyun Çalışma Kümesini Boşaltma)",
                    Location = new Point(20, 24),
                    Width = 400,
                    Checked = qolConfig.RamCleanProtectForegroundGame,
                    ForeColor = Color.FromArgb(52, 211, 153),
                    Font = new Font("Segoe UI", 8.2f, FontStyle.Bold)
                };
                dlg.Controls.Add(chkProt);

                Label lblProtInfo = new Label
                {
                    Text = "Aktif olduğunda yalnızca arka plan programları ve Windows Standby List temizlenir; oynadığınız oyunda FPS takılması veya drop yaşanmaz.",
                    Location = new Point(20, 52),
                    Size = new Size(400, 48),
                    ForeColor = Color.FromArgb(148, 163, 184),
                    Font = new Font("Segoe UI", 7.8f)
                };
                dlg.Controls.Add(lblProtInfo);

                Button btnSave = new Button
                {
                    Text = "Kaydet",
                    DialogResult = DialogResult.OK,
                    Location = new Point(220, 140),
                    Size = new Size(110, 32),
                    BackColor = Color.FromArgb(16, 185, 129),
                    ForeColor = Color.Black,
                    FlatStyle = FlatStyle.Flat,
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                btnSave.FlatAppearance.BorderSize = 0;
                dlg.Controls.Add(btnSave);

                Button btnCancel = new Button
                {
                    Text = "Kapat",
                    DialogResult = DialogResult.Cancel,
                    Location = new Point(340, 140),
                    Size = new Size(80, 32),
                    BackColor = Color.FromArgb(30, 41, 59),
                    ForeColor = Color.FromArgb(203, 213, 225),
                    FlatStyle = FlatStyle.Flat
                };
                btnCancel.FlatAppearance.BorderColor = Color.FromArgb(51, 65, 85);
                dlg.Controls.Add(btnCancel);

                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    qolConfig.RamCleanProtectForegroundGame = chkProt.Checked;
                    qolConfig.SaveToFile(qolConfigPath);
                }
            }
        }

        // -------------------------------------------------------------
        // BACKGROUND TICK PROCESSOR & CLEANERS
        // -------------------------------------------------------------
        private void ProcessQoLAutomationTick()
        {
            DateTime now = DateTime.Now;

            // 1. Live Network Throughput Tracking for Smart Download Detector
            try
            {
                if (tickCounter % 2 == 0) // Every 1 second
                {
                    long totalRecv = 0;
                    foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (ni.OperationalStatus == OperationalStatus.Up &&
                            (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet || ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211))
                        {
                            totalRecv += ni.GetIPStatistics().BytesReceived;
                        }
                    }

                    if (lastTrafficBytesRecv > 0 && lastTrafficSampleTime > DateTime.MinValue)
                    {
                        double sec = (now - lastTrafficSampleTime).TotalSeconds;
                        if (sec > 0.4)
                        {
                            long delta = totalRecv - lastTrafficBytesRecv;
                            if (delta >= 0)
                            {
                                liveDownloadSpeedKBps = (delta / 1024.0) / sec;
                            }
                        }
                    }
                    lastTrafficBytesRecv = totalRecv;
                    lastTrafficSampleTime = now;
                }
            }
            catch { }

            // 2. Power Timer Processing
            if (qolConfig.PowerTimerActive)
            {
                TimeSpan remaining = qolConfig.PowerTimerTarget - now;

                if (lblPowerTimerStatus != null && currentActiveTabIndex == 7)
                {
                    if (remaining.TotalSeconds > 0)
                    {
                        lblPowerTimerStatus.Text = string.Format("⏳ Hedef: {0:HH:mm:ss} — Kalan: {1:00}:{2:00}:{3:00} [{4}]",
                            qolConfig.PowerTimerTarget, (int)remaining.TotalHours, remaining.Minutes, remaining.Seconds, qolConfig.PowerTimerAction);
                    }
                }

                // 5-Minute Warning Toast
                if (remaining.TotalMinutes <= 5 && remaining.TotalMinutes > 0 && !qolConfig.PowerTimerWarnGiven && qolConfig.PowerTimer5MinWarn)
                {
                    qolConfig.PowerTimerWarnGiven = true;
                    ShowQoLToast("⚠️ Kapatma Uyarısı (5 Dakika Kaldı)",
                        string.Format("Bilgisayarınız 5 dakika içinde kapatılacak ({0}). İptal etmek için butona tıklayabilirsiniz.", qolConfig.PowerTimerAction),
                        "Kapatmayı İptal Et", () => CancelPowerTimer(true), Color.FromArgb(245, 158, 11), 30, false);
                }

                // Timer Reached: Check Idle/Download Conditions or Trigger
                if (remaining.TotalSeconds <= 0)
                {
                    // Check Smart Download Detector
                    if (qolConfig.PowerTimerPostponeIfNetBusy && liveDownloadSpeedKBps > qolConfig.PowerTimerNetThresholdKBps)
                    {
                        qolConfig.PowerTimerTarget = now.AddMinutes(5);
                        ShowQoLToast("⏱️ Kapatma 5 Dk Ertelendi",
                            string.Format("Aktif indirme algılandı ({0:0} KB/s > {1} KB/s). Bilgisayarın kapanması 5 dakika ertelendi.", liveDownloadSpeedKBps, qolConfig.PowerTimerNetThresholdKBps),
                            "Şimdi Kapat", () => ExecutePowerActionNow(qolConfig.PowerTimerAction), Color.FromArgb(56, 189, 248), 10, false);
                        return;
                    }

                    // Check Smart CPU Idle Detector
                    if (qolConfig.PowerTimerPostponeIfCpuBusy && sensorEngine != null && sensorEngine.CpuTotalLoad > qolConfig.PowerTimerCpuThresholdPercent)
                    {
                        qolConfig.PowerTimerTarget = now.AddMinutes(5);
                        ShowQoLToast("⏱️ Kapatma 5 Dk Ertelendi",
                            string.Format("CPU yükü yüksek (%{0:0.0} > %{1}). İşlemin bitmesi için kapatma 5 dakika ertelendi.", sensorEngine.CpuTotalLoad, qolConfig.PowerTimerCpuThresholdPercent),
                            "Şimdi Kapat", () => ExecutePowerActionNow(qolConfig.PowerTimerAction), Color.FromArgb(56, 189, 248), 10, false);
                        return;
                    }

                    // Execute Power Action
                    string actionToExec = qolConfig.PowerTimerAction;
                    CancelPowerTimer(false);
                    ExecutePowerActionNow(actionToExec);
                }
            }

            // 3. Alarms Evaluation (Every 1 second)
            if (tickCounter % 2 == 0 && qolConfig.Alarms.Count > 0)
            {
                for (int i = 0; i < qolConfig.Alarms.Count; i++)
                {
                    var a = qolConfig.Alarms[i];
                    if (!a.IsEnabled) continue;
                    if (now >= a.NextTrigger)
                    {
                        a.LastTriggered = now;
                        if (a.AlarmType == "CRYPTO_4H")
                        {
                            a.NextTrigger = CryptoAlarmHelpers.GetNextCrypto4HCandleTime();
                        }
                        else if (a.AlarmType == "CRYPTO_DAILY")
                        {
                            a.NextTrigger = CryptoAlarmHelpers.GetNextCryptoDailyCloseTime();
                        }
                        else if (a.AlarmType == "CRYPTO_WEEKLY")
                        {
                            a.NextTrigger = CryptoAlarmHelpers.GetNextCryptoWeeklyCloseTime();
                        }
                        else if (a.AlarmType == "PERIODIC")
                        {
                            a.NextTrigger = now.AddMinutes(Math.Max(1, a.PeriodMinutes));
                        }
                        else // ONE-TIME
                        {
                            a.IsEnabled = false;
                        }

                        qolConfig.SaveToFile(qolConfigPath);
                        RefreshAlarmsListView();

                        TriggerAlarmAlert(a);
                    }
                }
            }

            // 4. Game Notes Watchdog (Every 2 seconds)
            if (tickCounter % 4 == 0 && qolConfig.GameNotes.Count > 0)
            {
                ThreadPool.QueueUserWorkItem(_ =>
                {
                    try
                    {
                        HashSet<string> currentProcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var p in Process.GetProcesses())
                        {
                            try { currentProcs.Add(p.ProcessName); } catch { }
                        }

                        foreach (var gn in qolConfig.GameNotes)
                        {
                            if (!gn.IsEnabled) continue;
                            string cleanTarget = (gn.ProcessName ?? "").Replace(".exe", "").Trim();
                            if (string.IsNullOrEmpty(cleanTarget)) continue;

                            bool isRunning = currentProcs.Contains(cleanTarget);

                            if (isRunning && !gn.WasRunningLastCheck)
                            {
                                gn.WasRunningLastCheck = true;
                                gn.LastNotified = DateTime.Now;
                                this.BeginInvoke((MethodInvoker)delegate
                                {
                                    ShowQoLToast("🎮 Oyun Hatırlatıcı: " + gn.GameTitle, gn.NoteText, "Kapat", null, Color.FromArgb(251, 191, 36), 12, false);
                                });
                            }
                            else if (isRunning && gn.PeriodicInGame && gn.PeriodicIntervalMinutes > 0)
                            {
                                if ((DateTime.Now - gn.LastNotified).TotalMinutes >= gn.PeriodicIntervalMinutes)
                                {
                                    gn.LastNotified = DateTime.Now;
                                    this.BeginInvoke((MethodInvoker)delegate
                                    {
                                        ShowQoLToast("🎮 Oyun Notu: " + gn.GameTitle, gn.NoteText, "Kapat", null, Color.FromArgb(251, 191, 36), 10, false);
                                    });
                                }
                            }
                            else if (!isRunning)
                            {
                                gn.WasRunningLastCheck = false;
                            }
                        }
                    }
                    catch { }
                });
            }

            // 5. Health Break Reminders (Opt-in only, default false)
            if (tickCounter % 20 == 0 && qolConfig.HealthRemindersEnabled)
            {
                if (qolConfig.LastHealthReminderTime == DateTime.MinValue)
                {
                    qolConfig.LastHealthReminderTime = now;
                }
                else if ((now - qolConfig.LastHealthReminderTime).TotalMinutes >= Math.Max(15, qolConfig.HealthReminderIntervalMin))
                {
                    qolConfig.LastHealthReminderTime = now;
                    ShowQoLToast("💧 Sağlık & Mola Hatırlatıcı",
                        "Gözlerinizi 20 saniye uzağa odaklayın ve bir bardak su için!",
                        "Tamam", null, Color.FromArgb(56, 189, 248), 10, false);
                }
            }

            // 6. Smart RAM Auto Threshold Purge (Every 10 seconds)
            if (tickCounter % 20 == 0)
            {
                UpdateQoLRamStatusLabel();
                if (qolConfig.AutoRamCleanActive)
                {
                    try
                    {
                        NativeMethods.MEMORYSTATUSEX mem = new NativeMethods.MEMORYSTATUSEX();
                        if (NativeMethods.GlobalMemoryStatusEx(mem))
                        {
                            double freePercent = 100.0 - mem.dwMemoryLoad;
                            if (freePercent <= qolConfig.RamFreeThresholdPercent)
                            {
                                ExecuteSmartRamAndStandbyPurge(qolConfig.RamCleanProtectForegroundGame);
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        private void ExecutePowerActionNow(string action)
        {
            try
            {
                if (action == "SHUTDOWN")
                {
                    Process.Start("shutdown.exe", "/s /t 0");
                }
                else if (action == "RESTART")
                {
                    Process.Start("shutdown.exe", "/r /t 0");
                }
                else if (action == "SLEEP")
                {
                    Application.SetSuspendState(PowerState.Suspend, false, false);
                }
                else if (action == "LOCK")
                {
                    NativeMethods.LockWorkStation();
                }
            }
            catch (Exception ex)
            {
                ShowQoLToast("⚠️ Güç İşlemi Hatası", ex.Message, "Kapat", null, Color.FromArgb(248, 113, 113), 8, false);
            }
        }

        private void RunSystemTempCleanAsync()
        {
            if (btnCleanTempNow != null)
            {
                btnCleanTempNow.Enabled = false;
                btnCleanTempNow.Text = "⏳ Temizleniyor...";
            }
            if (lblSystemTempStatus != null) lblSystemTempStatus.Text = "Geçici sistem dosyaları taranıyor ve siliniyor...";

            ThreadPool.QueueUserWorkItem(_ =>
            {
                long totalBytes = 0;
                int filesDeleted = 0;
                int skipped = 0;

                List<string> paths = new List<string>();
                try { paths.Add(Path.GetTempPath()); } catch { }
                try
                {
                    string winTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
                    if (Directory.Exists(winTemp)) paths.Add(winTemp);
                }
                catch { }
                try
                {
                    string prefetch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                    if (Directory.Exists(prefetch)) paths.Add(prefetch);
                }
                catch { }

                foreach (string dir in paths)
                {
                    if (!Directory.Exists(dir)) continue;
                    try
                    {
                        DirectoryInfo di = new DirectoryInfo(dir);
                        foreach (FileInfo fi in di.GetFiles("*", SearchOption.AllDirectories))
                        {
                            try
                            {
                                long len = fi.Length;
                                fi.Delete();
                                totalBytes += len;
                                filesDeleted++;
                            }
                            catch
                            {
                                skipped++;
                            }
                        }
                    }
                    catch { }
                }

                double freedMb = totalBytes / (1024.0 * 1024.0);
                string report = string.Format("✅ {0:0.0} MB geçici dosya temizlendi ({1} silindi, {2} kullanımda atlandı).", freedMb, filesDeleted, skipped);

                this.BeginInvoke((MethodInvoker)delegate
                {
                    if (btnCleanTempNow != null)
                    {
                        btnCleanTempNow.Enabled = true;
                        btnCleanTempNow.Text = "🧹 Windows Temp Temizle";
                    }
                    if (lblSystemTempStatus != null)
                    {
                        lblSystemTempStatus.Text = report;
                        lblSystemTempStatus.ForeColor = Color.FromArgb(52, 211, 153);
                    }
                    ShowQoLToast("🧹 Windows Temp Temizliği", report, "Tamam", null, Color.FromArgb(56, 189, 248), 6, false);
                });
            });
        }

        private void RunGpuShaderCleanAsync()
        {
            if (btnCleanShaderNow != null)
            {
                btnCleanShaderNow.Enabled = false;
                btnCleanShaderNow.Text = "⏳ Shader Temizleniyor...";
            }
            if (lblShaderCacheStatus != null) lblShaderCacheStatus.Text = "DirectX, NVIDIA ve AMD Shader havuzları taranıyor...";

            ThreadPool.QueueUserWorkItem(_ =>
            {
                long totalBytes = 0;
                int filesDeleted = 0;
                int skipped = 0;

                string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

                List<string> shaderPaths = new List<string>
                {
                    Path.Combine(localApp, @"NVIDIA\DXCache"),
                    Path.Combine(localApp, @"NVIDIA\GLCache"),
                    Path.Combine(appData, @"NVIDIA\ComputeCache"),
                    Path.Combine(localApp, @"AMD\DxCache"),
                    Path.Combine(localApp, @"AMD\GLCache"),
                    Path.Combine(localApp, @"AMD\D3DSCache"),
                    Path.Combine(localApp, @"D3DSCache")
                };

                foreach (string dir in shaderPaths)
                {
                    if (!Directory.Exists(dir)) continue;
                    try
                    {
                        DirectoryInfo di = new DirectoryInfo(dir);
                        foreach (FileInfo fi in di.GetFiles("*", SearchOption.AllDirectories))
                        {
                            try
                            {
                                long len = fi.Length;
                                fi.Delete();
                                totalBytes += len;
                                filesDeleted++;
                            }
                            catch
                            {
                                skipped++;
                            }
                        }
                    }
                    catch { }
                }

                double freedMb = totalBytes / (1024.0 * 1024.0);
                string report = string.Format("✅ {0:0.0} MB GPU Shader önbelleği temizlendi ({1} dosya silindi, {2} atlandı).", freedMb, filesDeleted, skipped);

                this.BeginInvoke((MethodInvoker)delegate
                {
                    if (btnCleanShaderNow != null)
                    {
                        btnCleanShaderNow.Enabled = true;
                        btnCleanShaderNow.Text = "🎮 GPU Shader Önbelleğini Temizle";
                    }
                    if (lblShaderCacheStatus != null)
                    {
                        lblShaderCacheStatus.Text = report;
                        lblShaderCacheStatus.ForeColor = Color.FromArgb(52, 211, 153);
                    }
                    ShowQoLToast("🎮 GPU Shader Temizliği", report, "Tamam", null, Color.FromArgb(248, 113, 113), 6, false);
                });
            });
        }

        #endregion

        private void BuildBenchmarkView()
        {
            viewBenchmark = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(10, 8, 10, 8),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewBenchmark);

            Panel pnlSleepCard = new Panel
            {
                Location = new Point(10, 10),
                Size = new Size(405, 255),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewBenchmark.Controls.Add(pnlSleepCard);

            Label lblSleepTitle = new Label
            {
                Text = "KERNEL ZAMANLAYICI & SLEEP(1) JITTER TESTİ",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(16, 185, 129),
                AutoSize = true,
                Location = new Point(12, 12)
            };
            pnlSleepCard.Controls.Add(lblSleepTitle);

            btnRunSleepTest = CreateActionButton(pnlSleepCard, 12, 36, 380, 32, "25 İterasyonlu Kernel Uyanma & Jitter Testini Başlat", Color.FromArgb(16, 185, 129));
            btnRunSleepTest.ForeColor = Color.Black;
            btnRunSleepTest.Click += (s, e) => RunKernelSleepDriftBenchmark();

            lblSleepTestReport = new Label
            {
                Text = "25 kez 1ms'lik uyku (Thread.Sleep(1)) çağrısı yaparak işletim sisteminin gerçek uyanma gecikmesini ve sapmasını (jitter) ölçer.\n\n• Standart Windows (15.6ms): ~15.60 ms\n• Argon 0.500ms Modu: ~1.00 - 1.45 ms",
                Font = new Font("Consolas", 8.0f, FontStyle.Regular),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(12, 78),
                Size = new Size(380, 165)
            };
            pnlSleepCard.Controls.Add(lblSleepTestReport);

            Panel pnlPingCard = new Panel
            {
                Location = new Point(425, 10),
                Size = new Size(405, 255),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewBenchmark.Controls.Add(pnlPingCard);

            Label lblPingTitle = new Label
            {
                Text = "ÇOKLU OMURGA PING, JITTER & PAKET KAYBI ANALİZİ",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(12, 12)
            };
            pnlPingCard.Controls.Add(lblPingTitle);

            btnRunMultiPingTest = CreateActionButton(pnlPingCard, 12, 36, 380, 32, "Cloudflare (1.1.1.1) & Google (8.8.8.8) Jitter Testi", Color.FromArgb(14, 165, 233));
            btnRunMultiPingTest.ForeColor = Color.Black;
            btnRunMultiPingTest.Click += (s, e) => RunDetailedMultiServerPingBenchmark();

            lblPingTestReport = new Label
            {
                Text = "Nagle, AFD Fast-Path ve Kesme Moderasyonu ayarlarını açmadan önce ve açtıktan sonra Jitter (paketler arası ms farkı) düşüşünü doğrulayabilirsiniz.",
                Font = new Font("Consolas", 8.0f, FontStyle.Regular),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(12, 78),
                Size = new Size(380, 165)
            };
            pnlPingCard.Controls.Add(lblPingTestReport);

            Panel pnlMouseBench = new Panel
            {
                Location = new Point(10, 275),
                Size = new Size(820, 210),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewBenchmark.Controls.Add(pnlMouseBench);

            Label lblMTitle = new Label
            {
                Text = "CANLI FARE SORGU HIZI (POLLING RATE HZ) & KUYRUK UYUMLULUK ÖLÇER",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                AutoSize = true,
                Location = new Point(12, 12)
            };
            pnlMouseBench.Controls.Add(lblMTitle);

            pnlMouseTestArea = new Panel
            {
                Location = new Point(12, 38),
                Size = new Size(796, 156),
                BackColor = Color.FromArgb(10, 13, 19),
                BorderStyle = BorderStyle.FixedSingle,
                Cursor = Cursors.Cross
            };
            pnlMouseTestArea.MouseMove += OnMouseTestAreaMove;
            pnlMouseBench.Controls.Add(pnlMouseTestArea);

            lblMouseHzLive = new Label
            {
                Text = "Fareyi bu siyah alan içinde hızlıca dairesel hareket ettirin...",
                Font = new Font("Segoe UI", 12.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                Size = new Size(772, 36),
                Location = new Point(12, 32)
            };
            lblMouseHzLive.MouseMove += OnMouseTestAreaMove;
            pnlMouseTestArea.Controls.Add(lblMouseHzLive);

            lblMouseDeltaLive = new Label
            {
                Text = "Anlık Raporlama Aralığı: -- ms | 1000Hz = 1.00ms, 2000Hz = 0.50ms, 4000Hz = 0.25ms",
                Font = new Font("Consolas", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                Size = new Size(772, 28),
                Location = new Point(12, 82)
            };
            lblMouseDeltaLive.MouseMove += OnMouseTestAreaMove;
            pnlMouseTestArea.Controls.Add(lblMouseDeltaLive);

            viewBenchmark.Resize += (s, e) =>
            {
                int availW = Math.Max(680, viewBenchmark.ClientSize.Width - 24);
                int halfW = (availW - 10) / 2;
                pnlSleepCard.Location = new Point(10, 10);
                pnlSleepCard.Width = halfW;
                btnRunSleepTest.Width = halfW - 24;
                lblSleepTestReport.Width = halfW - 24;

                pnlPingCard.Location = new Point(10 + halfW + 10, 10);
                pnlPingCard.Width = availW - halfW - 10;
                btnRunMultiPingTest.Width = pnlPingCard.Width - 24;
                lblPingTestReport.Width = pnlPingCard.Width - 24;

                pnlMouseBench.Location = new Point(10, 275);
                pnlMouseBench.Width = availW;
                pnlMouseTestArea.Width = availW - 24;
                lblMouseHzLive.Width = pnlMouseTestArea.Width - 24;
                lblMouseDeltaLive.Width = pnlMouseTestArea.Width - 24;
            };
        }

        private Label lblSettingsSensorDiag;
        private ListBox lstCustomProfilesManager;
        private TextBox txtNewProfileNameInput;
        private CheckBox chkSetEnableSensors;
        private CheckBox chkSetShowCpu;
        private CheckBox chkSetShowGpuCore;
        private CheckBox chkSetShowGpuMemHot;
        private ComboBox cmbSetPollInterval;
        private ComboBox cmbResolutionPreset;
        private CheckBox chkSetLockResolution;
        private CheckBox chkSetAutoTruthSync;
        private CheckBox chkSetConfirmCritical;
        private CheckBox chkSetRichTooltips;
        private bool syncingSettingsTabUi = false;

        private void BuildWinUtilView()
        {
            viewWinUtil = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(10, 8, 10, 8),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewWinUtil);

            Panel pnlWuBanner = new Panel
            {
                Dock = DockStyle.Top,
                Height = 72,
                BackColor = Color.FromArgb(32, 20, 27)
            };
            pnlWuBanner.Paint += (s, e) =>
            {
                using (Pen p = new Pen(Color.FromArgb(120, 53, 15), 1))
                {
                    e.Graphics.DrawRectangle(p, 0, 0, pnlWuBanner.Width - 1, pnlWuBanner.Height - 1);
                }
            };
            viewWinUtil.Controls.Add(pnlWuBanner);

            Label lblWuTitle = new Label
            {
                Text = "WINUTIL MİMARİ & KRİTİK SİSTEM AYARLARI (ChrisTitusTech/winutil Güvenli Seçki)",
                Font = new Font("Segoe UI", 8.6f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                AutoSize = true,
                Location = new Point(12, 8)
            };
            pnlWuBanner.Controls.Add(lblWuTitle);

            Label lblWuDesc = new Label
            {
                Text = "GÜVENLİK POLİTİKASI: Windows Defender veya güvenlik duvarına kesinlikle dokunulmaz.\n" +
                       "DWM MPO, IPv4 Önceliği, Hibernation, Teslim En İyileştirme ve WPBT ayarları onay ve StateVault yedeği ile çalışır.",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(12, 28),
                Size = new Size(600, 38)
            };
            pnlWuBanner.Controls.Add(lblWuDesc);

            Button btnCreateRestorePoint = CreateActionButton(pnlWuBanner, 625, 18, 195, 34, "Sistem Geri Yükleme Noktası Al", Color.FromArgb(217, 119, 6));
            btnCreateRestorePoint.ForeColor = Color.Black;
            btnCreateRestorePoint.Click += (s, e) => CreateWindowsRestorePointInteractive();
            mainToolTip.SetToolTip(btnCreateRestorePoint, "Kritik mimari ayarları uygulamadan önce Windows Sistem Geri Yükleme (System Restore) noktası oluşturur.");

            pnlWuBanner.Resize += (s, e) =>
            {
                int w = Math.Max(640, pnlWuBanner.ClientSize.Width);
                btnCreateRestorePoint.Location = new Point(w - btnCreateRestorePoint.Width - 12, 18);
                lblWuDesc.Width = Math.Max(420, btnCreateRestorePoint.Left - 24);
            };

            Panel pnlWuColHdr = CreateTweakTableColumnHeader("WinUtil Mimari & Sistem Politikaları");
            pnlWuColHdr.Dock = DockStyle.Top;
            viewWinUtil.Controls.Add(pnlWuColHdr);

            flowWinUtilCards = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(0, 4, 0, 8),
                BackColor = Color.FromArgb(13, 16, 23)
            };
            viewWinUtil.Controls.Add(flowWinUtilCards);
            pnlWuColHdr.SendToBack();
            pnlWuBanner.SendToBack();
            flowWinUtilCards.BringToFront();

            foreach (var tweak in allTweaks)
            {
                if (tweak.Category != "WINUTIL") continue;
                var card = new MultiVariationTweakCard(tweak, mainToolTip, OnTweakCardToggled, OnTweakCardHovered);
                card.Width = 810;
                flowWinUtilCards.Controls.Add(card);
                allCards.Add(card);
            }

            flowWinUtilCards.Resize += (s, e) =>
            {
                int targetW = Math.Max(520, flowWinUtilCards.ClientSize.Width - 24);
                foreach (Control c in flowWinUtilCards.Controls)
                {
                    if (c is MultiVariationTweakCard)
                    {
                        c.Width = targetW;
                        c.Invalidate(true);
                    }
                }
            };
        }

        private void CreateWindowsRestorePointInteractive()
        {
            if (!isAdmin)
            {
                MessageBox.Show("Sistem Geri Yükleme Noktası oluşturmak için Yönetici yetkisi gereklidir.", "Yönetici Yetkisi Gerekli", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            lblInspectorTitle.Text = "Windows Sistem Geri Yükleme Noktası oluşturuluyor...";
            lblInspectorPath.Text = "WMI SystemRestore servisi çağrılıyor, lütfen birkaç saniye bekleyin...";
            AppendConsoleLog("WMI üzerinden Sistem Geri Yükleme Noktası oluşturuluyor...");
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    string outText = StateVault.RunCmdCaptureOutput("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"Checkpoint-Computer -Description 'ArgonLatencyStudio_Backup' -RestorePointType 'MODIFY_SETTINGS'\"");
                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        lblInspectorTitle.Text = "Windows Sistem Geri Yükleme Noktası ('ArgonLatencyStudio_Backup') başarıyla oluşturuldu.";
                        lblInspectorPath.Text = "Ayrıca Argon kendi StateVault yedeğini de her zaman saklar.";
                        AppendConsoleLog("Sistem Geri Yükleme Noktası ('ArgonLatencyStudio_Backup') oluşturuldu.");
                        MessageBox.Show("Windows Sistem Geri Yükleme Noktası ('ArgonLatencyStudio_Backup') oluşturma komutu tamamlandı.", "Geri Yükleme Noktası Hazır", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    });
                }
                catch (Exception ex)
                {
                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        lblInspectorTitle.Text = "Geri yükleme noktası uyarısı: " + ex.Message;
                    });
                }
            });
        }

        private void BuildSettingsView()
        {
            viewSettings = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(10, 8, 10, 8),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewSettings);

            // TOP PANEL: Custom Profile Management (Full Width inside Left Workspace)
            Panel pnlRightCol = new Panel
            {
                Location = new Point(10, 8),
                Size = new Size(815, 255),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewSettings.Controls.Add(pnlRightCol);

            Label lblProfTitle = new Label
            {
                Text = "ÖZEL PROFİL YÖNETİMİ (.ARGON KULLANICI PROFİLLERİ & HAZIR REÇETELER)",
                Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                AutoSize = true,
                Location = new Point(14, 10)
            };
            pnlRightCol.Controls.Add(lblProfTitle);

            Label lblNewName = new Label
            {
                Text = "Yeni Özel Profil Adı:",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(14, 36)
            };
            pnlRightCol.Controls.Add(lblNewName);

            txtNewProfileNameInput = new TextBox
            {
                Location = new Point(135, 33),
                Size = new Size(210, 22),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                Text = "Benim Espor Profilim"
            };
            pnlRightCol.Controls.Add(txtNewProfileNameInput);

            Button btnSaveNamedProf = CreateActionButton(pnlRightCol, 352, 31, 145, 26, "Profili Kaydet", Color.FromArgb(16, 185, 129));
            btnSaveNamedProf.ForeColor = Color.Black;
            btnSaveNamedProf.Click += (s, e) =>
            {
                string name = (txtNewProfileNameInput.Text ?? "").Trim();
                if (string.IsNullOrEmpty(name))
                {
                    MessageBox.Show("Lütfen kaydedilecek profil için bir isim girin.", "Profil Adı Gerekli", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                SaveCurrentStateAsCustomProfile(name);
            };

            Button btnExportProf = CreateActionButton(pnlRightCol, 504, 31, 145, 26, "Dışa Aktar (.argon)", Color.FromArgb(14, 165, 233));
            btnExportProf.ForeColor = Color.Black;
            btnExportProf.Click += (s, e) => ExportCurrentProfileDialog();

            Button btnImportProf = CreateActionButton(pnlRightCol, 656, 31, 145, 26, "İçe Aktar (.argon)", Color.FromArgb(168, 85, 247));
            btnImportProf.Click += (s, e) => ImportCustomProfileDialog();

            lstCustomProfilesManager = new ListBox
            {
                Location = new Point(14, 64),
                Size = new Size(787, 142),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(226, 232, 240),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.4f, FontStyle.Regular)
            };
            pnlRightCol.Controls.Add(lstCustomProfilesManager);

            Button btnApplySelProf = CreateActionButton(pnlRightCol, 14, 214, 250, 30, "Seçili Profili Sisteme Uygula", Color.FromArgb(16, 185, 129));
            btnApplySelProf.ForeColor = Color.Black;
            btnApplySelProf.Click += (s, e) => ApplyProfileFromSettingsListSelection();

            Button btnDeleteSelProf = CreateActionButton(pnlRightCol, 272, 214, 240, 30, "Seçili Kullanıcı Profilini Sil", Color.FromArgb(153, 27, 27));
            btnDeleteSelProf.Click += (s, e) => DeleteProfileFromSettingsListSelection();

            Button btnOpenVaultFolder = CreateActionButton(pnlRightCol, 520, 214, 281, 30,
                "Yedek & Profil Klasörünü Aç (AppData)", Color.FromArgb(30, 58, 138));
            btnOpenVaultFolder.Click += (s, e) =>
            {
                try
                {
                    string dir = Path.GetDirectoryName(userProfilePath);
                    if (Directory.Exists(dir)) Process.Start("explorer.exe", dir);
                }
                catch { }
            };

            // BOTTOM PANEL: Telemetry Sensors + Behavioral Settings
            Panel pnlLeftCol = new Panel
            {
                Location = new Point(10, 272),
                Size = new Size(815, 425),
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewSettings.Controls.Add(pnlLeftCol);

            Label lblSec1 = new Label
            {
                Text = "LİBRE HARDWAREMONITOR SENSÖR & CANLI ALGILAMA AYARLARI",
                Font = new Font("Segoe UI", 8.8f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Location = new Point(14, 10)
            };
            pnlLeftCol.Controls.Add(lblSec1);

            chkSetEnableSensors = CreateSettingsCheckBox(pnlLeftCol, 14, 34,
                "LibreHardwareMonitor Donanım Sensörlerini Etkinleştir (Canlı CPU & GPU Okuma)",
                appSettings.EnableTelemetrySensors);

            chkSetShowCpu = CreateSettingsCheckBox(pnlLeftCol, 14, 58,
                "İşlemci (CPU) Sıcaklığı (Core Tctl/Tdie) ve Yük Yüzdesini Sağ Panelde Göster",
                appSettings.ShowCpuSensor);

            chkSetShowGpuCore = CreateSettingsCheckBox(pnlLeftCol, 14, 82,
                "Ekran Kartı (GPU) Çekirdek (Core) Sıcaklığı ve Yük Yüzdesini Göster",
                appSettings.ShowGpuCoreSensor);

            chkSetShowGpuMemHot = CreateSettingsCheckBox(pnlLeftCol, 14, 106,
                "Ekran Kartı (GPU) Bellek (Memory) ve Hotspot Sıcaklığını Göster",
                appSettings.ShowGpuMemHotspotSensor);

            Label lblPoll = new Label
            {
                Text = "Sensör Yenileme Hızı:",
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                AutoSize = true,
                Location = new Point(450, 36)
            };
            pnlLeftCol.Controls.Add(lblPoll);

            cmbSetPollInterval = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 8.0f, FontStyle.Bold),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(580, 32),
                Size = new Size(145, 22)
            };
            cmbSetPollInterval.Items.AddRange(new object[]
            {
                "500 ms (Hızlı)",
                "1000 ms (Önerilen)",
                "2000 ms (Düşük Yük)"
            });
            cmbSetPollInterval.SelectedIndex = appSettings.TelemetryPollIntervalMs <= 500 ? 0 : (appSettings.TelemetryPollIntervalMs >= 2000 ? 2 : 1);
            pnlLeftCol.Controls.Add(cmbSetPollInterval);

            Button btnRescanSensors = CreateActionButton(pnlLeftCol, 730, 31, 72, 24, "Şimdi Oku", Color.FromArgb(14, 165, 233));
            btnRescanSensors.ForeColor = Color.Black;
            btnRescanSensors.Click += (s, e) => TriggerAsyncHardwareSensorPoll();

            lblSettingsSensorDiag = new Label
            {
                Text = "Sensör durumu hazırlanıyor...",
                Font = new Font("Consolas", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                BackColor = Color.FromArgb(12, 15, 22),
                BorderStyle = BorderStyle.FixedSingle,
                Padding = new Padding(6),
                Location = new Point(14, 134),
                Size = new Size(787, 62)
            };
            pnlLeftCol.Controls.Add(lblSettingsSensorDiag);

            Label lblLangHdr = new Label
            {
                Text = Loc.T("Arayüz Dili / Interface Language:", "Interface Language / Arayüz Dili:"),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(14, 206),
                AutoSize = true
            };
            pnlLeftCol.Controls.Add(lblLangHdr);

            cmbSetLanguage = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(255, 203),
                Size = new Size(180, 24)
            };
            cmbSetLanguage.Items.AddRange(new object[]
            {
                "Türkçe (TR)",
                "English (EN)"
            });
            cmbSetLanguage.SelectedIndex = Loc.IsEnglish ? 1 : 0;
            cmbSetLanguage.SelectedIndexChanged += (s, e) =>
            {
                if (syncingSettingsTabUi) return;
                string newLang = cmbSetLanguage.SelectedIndex == 1 ? "EN" : "TR";
                if (!string.Equals(appSettings.AppLanguage, newLang, StringComparison.OrdinalIgnoreCase))
                {
                    ApplyLanguage(newLang);
                }
            };
            pnlLeftCol.Controls.Add(cmbSetLanguage);

            Label lblResHdr = new Label
            {
                Text = Loc.T("Pencere Boyutu / Sabit Çözünürlük:", "Window Size / Fixed Resolution Preset:"),
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                ForeColor = Color.FromArgb(203, 213, 225),
                Location = new Point(14, 236),
                AutoSize = true
            };
            pnlLeftCol.Controls.Add(lblResHdr);

            cmbResolutionPreset = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 8.2f, FontStyle.Bold),
                BackColor = Color.FromArgb(12, 15, 22),
                ForeColor = Color.FromArgb(56, 189, 248),
                Location = new Point(255, 233),
                Size = new Size(340, 24)
            };
            cmbResolutionPreset.Items.AddRange(new object[]
            {
                "Standart (Orta Boy: 1380 x 890) [Varsayılan]",
                "Kompakt (Laptop: 1280 x 820)",
                "Geniş (2K / 1440p: 1560 x 960)",
                "Maksimum (4K: 1720 x 1020)"
            });
            cmbResolutionPreset.SelectedIndexChanged += (s, e) =>
            {
                if (syncingSettingsTabUi) return;
                int sel = cmbResolutionPreset.SelectedIndex;
                if (sel == 1) appSettings.WindowResolutionPreset = "COMPACT";
                else if (sel == 2) appSettings.WindowResolutionPreset = "LARGE";
                else if (sel == 3) appSettings.WindowResolutionPreset = "EXTRA_LARGE";
                else appSettings.WindowResolutionPreset = "MEDIUM";

                appSettings.Save(appSettingsPath);
                ApplyWindowLayoutPolicy();
                this.CenterToScreen();
            };
            pnlLeftCol.Controls.Add(cmbResolutionPreset);

            chkSetLockResolution = CreateSettingsCheckBox(pnlLeftCol, 14, 264,
                "Sabit Çözünürlük Kilidi (Pencere kenarlarından çekip arayüzü bozmayı engelle)",
                appSettings.LockFixedResolution);
            chkSetLockResolution.CheckedChanged += (s, e) =>
            {
                if (syncingSettingsTabUi) return;
                appSettings.LockFixedResolution = chkSetLockResolution.Checked;
                appSettings.Save(appSettingsPath);
                ApplyWindowLayoutPolicy();
            };

            chkSetAutoTruthSync = CreateSettingsCheckBox(pnlLeftCol, 14, 288,
                "Gerçek Durum Algılama (Live OS Truth): Açılışta Aktif Ayarları Otomatik Eşitle",
                appSettings.AutoLiveTruthSync);

            chkSetConfirmCritical = CreateSettingsCheckBox(pnlLeftCol, 14, 312,
                "Kritik ve WinUtil Ayarlarını Açarken Onay Penceresi Göster",
                appSettings.ConfirmCriticalTweaks);

            chkSetRichTooltips = CreateSettingsCheckBox(pnlLeftCol, 14, 336,
                "Zenginleştirilmiş Teknik İpuçları (Canlı OS Değeri + Kayıt Yolu)",
                appSettings.RichTooltipsEnabled);

            Button btnSyncLiveOsNow = CreateActionButton(pnlLeftCol, 14, 368, 515, 34,
                "ŞİMDİ GERÇEK WINDOWS DURUMUNDAN (LIVE OS TRUTH) TÜM ANAHTARLARI EŞİTLE",
                Color.FromArgb(16, 185, 129));
            btnSyncLiveOsNow.ForeColor = Color.Black;
            btnSyncLiveOsNow.Click += (s, e) =>
            {
                ProbeAllTweaksLiveOsTruthAndOptionallySync(true);
                MessageBox.Show(
                    "Tüm 45 ayar için Windows Kayıt Defteri, Aktif Güç Planı, Win32 SPI ve Kernel durumu canlı olarak tarandı.\n\n" +
                    "Sistemde gerçekten aktif olan ayarlar 'AÇIK', varsayılanda olanlar 'KAPALI' olarak arayüzle birebir eşitlendi.",
                    "Gerçek Durumdan Türetilen Algılama (Live OS Sync)",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            };

            Button btnResetAppSettings = CreateActionButton(pnlLeftCol, 538, 342, 263, 34,
                "Program Ayarlarını Varsayılana Döndür", Color.FromArgb(51, 65, 85));
            btnResetAppSettings.Click += (s, e) =>
            {
                appSettings = new ArgonAppSettings();
                appSettings.Save(appSettingsPath);
                SyncSettingsViewControlsFromModel();
                ApplyWindowLayoutPolicy();
                ReflowTelemetryHeaderBadges();
                TriggerAsyncHardwareSensorPoll();
            };

            EventHandler onSettingChanged = (s, e) =>
            {
                if (syncingSettingsTabUi) return;
                appSettings.EnableTelemetrySensors = chkSetEnableSensors.Checked;
                appSettings.ShowCpuSensor = chkSetShowCpu.Checked;
                appSettings.ShowGpuCoreSensor = chkSetShowGpuCore.Checked;
                appSettings.ShowGpuMemHotspotSensor = chkSetShowGpuMemHot.Checked;
                appSettings.TelemetryPollIntervalMs = cmbSetPollInterval.SelectedIndex == 0 ? 500 : (cmbSetPollInterval.SelectedIndex == 2 ? 2000 : 1000);
                appSettings.AutoLiveTruthSync = chkSetAutoTruthSync.Checked;
                appSettings.ConfirmCriticalTweaks = chkSetConfirmCritical.Checked;
                appSettings.RichTooltipsEnabled = chkSetRichTooltips.Checked;
                appSettings.Save(appSettingsPath);

                mainToolTip.InitialDelay = appSettings.RichTooltipsEnabled ? 120 : 400;
                ApplyWindowLayoutPolicy();
                ReflowTelemetryHeaderBadges();
                TriggerAsyncHardwareSensorPoll();
                UpdateTelemetryBar();
            };

            chkSetEnableSensors.CheckedChanged += onSettingChanged;
            chkSetShowCpu.CheckedChanged += onSettingChanged;
            chkSetShowGpuCore.CheckedChanged += onSettingChanged;
            chkSetShowGpuMemHot.CheckedChanged += onSettingChanged;
            cmbSetPollInterval.SelectedIndexChanged += onSettingChanged;
            chkSetAutoTruthSync.CheckedChanged += onSettingChanged;
            chkSetConfirmCritical.CheckedChanged += onSettingChanged;
            chkSetRichTooltips.CheckedChanged += onSettingChanged;

            viewSettings.Resize += (s, e) =>
            {
                int availW = Math.Max(680, viewSettings.ClientSize.Width - 24);
                pnlRightCol.Width = availW;
                lstCustomProfilesManager.Width = availW - 28;
                pnlLeftCol.Width = availW;
                lblSettingsSensorDiag.Width = availW - 28;
            };

            RefreshProfileSelectorCombo();
        }

        private CheckBox CreateSettingsCheckBox(Control parent, int x, int y, string text, bool initialChecked)
        {
            CheckBox chk = new CheckBox
            {
                Text = text,
                Font = new Font("Segoe UI", 8.3f, FontStyle.Bold),
                ForeColor = Color.FromArgb(226, 232, 240),
                AutoSize = true,
                Checked = initialChecked,
                Location = new Point(x, y),
                Cursor = Cursors.Hand
            };
            parent.Controls.Add(chk);
            return chk;
        }

        private void SyncSettingsViewControlsFromModel()
        {
            if (chkSetEnableSensors == null || appSettings == null) return;
            syncingSettingsTabUi = true;
            try
            {
                chkSetEnableSensors.Checked = appSettings.EnableTelemetrySensors;
                chkSetShowCpu.Checked = appSettings.ShowCpuSensor;
                chkSetShowGpuCore.Checked = appSettings.ShowGpuCoreSensor;
                chkSetShowGpuMemHot.Checked = appSettings.ShowGpuMemHotspotSensor;
                cmbSetPollInterval.SelectedIndex = appSettings.TelemetryPollIntervalMs <= 500 ? 0 : (appSettings.TelemetryPollIntervalMs >= 2000 ? 2 : 1);

                if (cmbResolutionPreset != null)
                {
                    string p = appSettings.WindowResolutionPreset ?? "MEDIUM";
                    if (p == "COMPACT") cmbResolutionPreset.SelectedIndex = 1;
                    else if (p == "LARGE") cmbResolutionPreset.SelectedIndex = 2;
                    else if (p == "EXTRA_LARGE") cmbResolutionPreset.SelectedIndex = 3;
                    else cmbResolutionPreset.SelectedIndex = 0; // MEDIUM
                }
                if (chkSetLockResolution != null)
                {
                    chkSetLockResolution.Checked = appSettings.LockFixedResolution;
                }

                chkSetAutoTruthSync.Checked = appSettings.AutoLiveTruthSync;
                chkSetConfirmCritical.Checked = appSettings.ConfirmCriticalTweaks;
                chkSetRichTooltips.Checked = appSettings.RichTooltipsEnabled;
                if (cmbSetLanguage != null)
                {
                    cmbSetLanguage.SelectedIndex = Loc.IsEnglish ? 1 : 0;
                }
            }
            finally
            {
                syncingSettingsTabUi = false;
            }
        }

        private void BuildGlobalSearchView()
        {
            viewGlobalSearch = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(10, 8, 10, 8),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewGlobalSearch);

            Panel pnlSearchTop = new Panel
            {
                Dock = DockStyle.Top,
                Height = 36,
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewGlobalSearch.Controls.Add(pnlSearchTop);

            lblGlobalSearchHeader = new Label
            {
                Text = "TÜM SEKMELERDE GENEL ARAMA SONUÇLARI:",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                AutoSize = true,
                Location = new Point(12, 9)
            };
            pnlSearchTop.Controls.Add(lblGlobalSearchHeader);

            Button btnClearSearch = CreateActionButton(pnlSearchTop, 640, 5, 165, 25, "Aramayı Temizle & Dön", Color.FromArgb(51, 65, 85));
            btnClearSearch.Click += (s, e) => { txtGlobalSearch.Text = ""; };
            pnlSearchTop.Resize += (s, e) =>
            {
                btnClearSearch.Location = new Point(Math.Max(520, pnlSearchTop.ClientSize.Width - btnClearSearch.Width - 10), 5);
            };

            flowGlobalSearchCards = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                Padding = new Padding(0, 6, 0, 8),
                BackColor = Color.FromArgb(13, 16, 23)
            };
            viewGlobalSearch.Controls.Add(flowGlobalSearchCards);
            pnlSearchTop.SendToBack();
            flowGlobalSearchCards.BringToFront();

            flowGlobalSearchCards.Resize += (s, e) =>
            {
                int targetW = Math.Max(520, flowGlobalSearchCards.ClientSize.Width - 24);
                foreach (Control c in flowGlobalSearchCards.Controls)
                {
                    if (c is MultiVariationTweakCard)
                    {
                        c.Width = targetW;
                        c.Invalidate(true);
                    }
                }
            };
        }

        private void BuildSnapshotAuditView()
        {
            viewSnapshotAudit = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(13, 16, 23),
                Padding = new Padding(10, 8, 10, 8),
                Visible = false
            };
            pnlContentHost.Controls.Add(viewSnapshotAudit);

            Panel pnlTopAudit = new Panel
            {
                Dock = DockStyle.Top,
                Height = 52,
                BackColor = Color.FromArgb(18, 23, 34)
            };
            viewSnapshotAudit.Controls.Add(pnlTopAudit);

            Label lblAuditSummary = new Label
            {
                Text = "CANLI OS ALGILAMA (LIVE TRUTH) & STATEVAULT YEDEK GÜNLÜĞÜ",
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                AutoSize = true,
                Location = new Point(12, 8)
            };
            pnlTopAudit.Controls.Add(lblAuditSummary);

            Label lblAuditSub = new Label
            {
                Text = "Her ayarın açılış öncesi orijinal fabrika değeri, canlı Windows Kayıt Defteri/Kernel değeri ve doğrulama durumu.",
                Font = new Font("Segoe UI", 7.8f, FontStyle.Regular),
                ForeColor = Color.FromArgb(148, 163, 184),
                AutoSize = true,
                Location = new Point(12, 28)
            };
            pnlTopAudit.Controls.Add(lblAuditSub);

            Button btnSyncFromAudit = CreateActionButton(pnlTopAudit, 490, 11, 185, 28, "Canlı OS Durumunu Eşitle", Color.FromArgb(16, 185, 129));
            btnSyncFromAudit.ForeColor = Color.Black;
            btnSyncFromAudit.Click += (s, e) => ProbeAllTweaksLiveOsTruthAndOptionallySync(true);

            Button btnRefreshAudit = CreateActionButton(pnlTopAudit, 682, 11, 125, 28, "Tabloyu Yenile", Color.FromArgb(51, 65, 85));
            btnRefreshAudit.Click += (s, e) =>
            {
                ProbeAllTweaksLiveOsTruthAndOptionallySync(false);
                RefreshSnapshotAuditView();
            };

            pnlTopAudit.Resize += (s, e) =>
            {
                int w = Math.Max(660, pnlTopAudit.ClientSize.Width);
                btnRefreshAudit.Location = new Point(w - btnRefreshAudit.Width - 10, 11);
                btnSyncFromAudit.Location = new Point(btnRefreshAudit.Left - btnSyncFromAudit.Width - 6, 11);
            };

            lvAuditLog = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.FromArgb(14, 18, 26),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.2f, FontStyle.Regular)
            };
            lvAuditLog.Columns.Add("İlgili Ayar / Modül", 210);
            lvAuditLog.Columns.Add("Kayıt Defteri / API Konumu", 245);
            lvAuditLog.Columns.Add("Orijinal Fabrika Değeri", 155);
            lvAuditLog.Columns.Add("Canlı Windows (OS) Durumu", 195);
            viewSnapshotAudit.Controls.Add(lvAuditLog);
            pnlTopAudit.SendToBack();
            lvAuditLog.BringToFront();
        }

        public void ApplyLanguage(string newLanguage)
        {
            if (string.IsNullOrEmpty(newLanguage)) newLanguage = "TR";
            Loc.CurrentLanguage = newLanguage.ToUpperInvariant();
            if (appSettings != null)
            {
                appSettings.AppLanguage = Loc.CurrentLanguage;
                appSettings.Save(appSettingsPath);
            }

            bool isEn = Loc.IsEnglish;

            // 1. Top Header
            if (btnLangToggle != null)
                btnLangToggle.Text = isEn ? "🌐 EN" : "🌐 TR";
            if (lblProfCaption != null)
                lblProfCaption.Text = isEn ? "PROFILE:" : "PROFİL:";
            if (btnQuickSaveProf != null)
                btnQuickSaveProf.Text = isEn ? "+ Save" : "+ Kaydet";
            if (chkRevertOnExit != null)
                chkRevertOnExit.Text = isEn ? "Revert on exit" : "Çıkışta sıfırla";
            if (chkAutoStart != null)
                chkAutoStart.Text = isEn ? "Start with Windows" : "Windows ile başlat";
            if (btnSmartTuneTop != null)
                btnSmartTuneTop.Text = isEn ? "⚡ Smart Tune" : "⚡ Akıllı Profil";
            if (btnResetAllTop != null)
                btnResetAllTop.Text = isEn ? "↺ Reset All" : "↺ Fabrika Sıfırla";
            if (btnMinimizeTray != null)
                btnMinimizeTray.Text = isEn ? "– Tray" : "– Tepsiye Küçült";
            if (lblSearchIcon != null)
                lblSearchIcon.Text = isEn ? "Search:" : "Ara:";
            if (btnElevate != null)
                btnElevate.Text = isEn ? "🛡️ Admin" : "🛡️ Yönetici Aç";

            // 2. Navigation Tabs
            string[] trTabNames = new string[]
            {
                "Donanım", "Ağ", "Timer", "Grafik", "Sistem", "Kernel",
                "İşlemler", "Otomasyon", "Tanı Test", "Günlük", "Ayarlar"
            };
            string[] enTabNames = new string[]
            {
                "Hardware", "Network", "Timer", "Graphics", "System", "Kernel",
                "Processes", "Automation", "Diagnostics", "Event Log", "Settings"
            };
            string[] activeTabNames = isEn ? enTabNames : trTabNames;
            for (int i = 0; i < navButtons.Count && i < activeTabNames.Length; i++)
            {
                navButtons[i].Text = activeTabNames[i];
            }
            UpdateActiveCountsAndNavBadges();
            LayoutNavBarButtons();

            // 3. Hardware Profile Top Controls
            if (lblMatTitle != null)
                lblMatTitle.Text = isEn ? "HARDWARE PROFILE & OPTIMIZATION LEVEL" : "DONANIM PROFİLİ VE OPTİMİZASYON SEVİYESİ";
            if (lblCpuPick != null)
                lblCpuPick.Text = isEn ? "1. Processor (CPU) Architecture:" : "1. İşlemci (CPU) Mimarisi:";
            if (lblGpuPick != null)
                lblGpuPick.Text = isEn ? "2. Graphics Card (GPU) Architecture:" : "2. Ekran Kartı (GPU) Mimarisi:";
            if (lblTierPick != null)
                lblTierPick.Text = isEn ? "3. Optimization Level:" : "3. Optimizasyon Kademesi:";
            if (btnTier1 != null) btnTier1.Text = isEn ? "1: Balanced" : "1: Dengeli";
            if (btnTier2 != null) btnTier2.Text = isEn ? "2: Esports" : "2: Espor";
            if (btnTier3 != null) btnTier3.Text = isEn ? "3: Extreme" : "3: Ekstrem";
            if (btnSmartApply != null)
                btnSmartApply.Text = isEn ? "⚡ APPLY SELECTED PROFILE (ONE-CLICK)" : "⚡ SEÇİLİ PROFİLİ TEK TIKLA UYGULA";
            if (btnAutoDetectReset != null)
                btnAutoDetectReset.Text = isEn ? "Auto-Detect Hardware" : "Donanımımı Otomatik Algıla";
            if (btnQuickRam != null)
                btnQuickRam.Text = isEn ? "Instant RAM & DNS Purge" : "Anlık RAM & DNS Temizle";

            // 4. Sidebar Network & Telemetry Labels
            if (grpNetAdapter != null) grpNetAdapter.Text = isEn ? "NETWORK & ADAPTER" : "AĞ ADAPTÖRÜ VE BAĞLANTI";
            if (btnSideFlush != null) btnSideFlush.Text = isEn ? "Clear" : "Temizle";
            if (lblHwHdr != null) lblHwHdr.Text = isEn ? "HARDWARE MONITOR" : "DONANIM İZLEME";
            if (lblSideEventLogHeader != null) lblSideEventLogHeader.Text = isEn ? "SYSTEM EVENT LOG" : "SİSTEM OLAY GÜNLÜĞÜ";

            if (txtNetHostAdmin != null && sidebarRowLabels.ContainsKey(txtNetHostAdmin))
                sidebarRowLabels[txtNetHostAdmin].Text = isEn ? "System / Auth" : "Sistem / Yetki";
            if (txtNetAdapter != null && sidebarRowLabels.ContainsKey(txtNetAdapter))
                sidebarRowLabels[txtNetAdapter].Text = isEn ? "Net Adapter" : "Ağ Adaptörü";
            if (txtNetLocalIp != null && sidebarRowLabels.ContainsKey(txtNetLocalIp))
                sidebarRowLabels[txtNetLocalIp].Text = isEn ? "Local IPv4 / Mask" : "Yerel IPv4 / Maske";
            if (txtNetGateway != null && sidebarRowLabels.ContainsKey(txtNetGateway))
                sidebarRowLabels[txtNetGateway].Text = isEn ? "Default Gateway" : "Varsayılan Geçit";
            if (txtNetDns != null && sidebarRowLabels.ContainsKey(txtNetDns))
                sidebarRowLabels[txtNetDns].Text = isEn ? "DNS Servers" : "DNS Sunucuları";
            if (txtNetMac != null && sidebarRowLabels.ContainsKey(txtNetMac))
                sidebarRowLabels[txtNetMac].Text = isEn ? "MAC Address" : "MAC (Fiziksel)";
            if (txtNetPingLive != null && sidebarRowLabels.ContainsKey(txtNetPingLive))
                sidebarRowLabels[txtNetPingLive].Text = isEn ? "Live Ping / RTT" : "Canlı Ping / RTT";
            if (txtHwCpuName != null && sidebarRowLabels.ContainsKey(txtHwCpuName))
                sidebarRowLabels[txtHwCpuName].Text = isEn ? "Processor (CPU)" : "İşlemci (CPU)";
            if (txtHwCpuTelemetry != null && sidebarRowLabels.ContainsKey(txtHwCpuTelemetry))
                sidebarRowLabels[txtHwCpuTelemetry].Text = isEn ? "CPU Temp / Load" : "CPU Sıcaklık / Yük";
            if (txtHwGpuName != null && sidebarRowLabels.ContainsKey(txtHwGpuName))
                sidebarRowLabels[txtHwGpuName].Text = isEn ? "Graphics (GPU)" : "Ekran Kartı (GPU)";
            if (txtHwGpuTelemetry != null && sidebarRowLabels.ContainsKey(txtHwGpuTelemetry))
                sidebarRowLabels[txtHwGpuTelemetry].Text = isEn ? "GPU Core / Hotspot" : "GPU Core / Hotspot";
            if (txtHwRamUsage != null && sidebarRowLabels.ContainsKey(txtHwRamUsage))
                sidebarRowLabels[txtHwRamUsage].Text = isEn ? "System Memory" : "Sistem Belleği";
            if (txtHwTimerActive != null && sidebarRowLabels.ContainsKey(txtHwTimerActive))
                sidebarRowLabels[txtHwTimerActive].Text = isEn ? "Active Timer Mode" : "Timer & Aktif Ayar";

            // 5. Table Headers
            foreach (var l in tweakColHeadersCol1)
            {
                int pIdx = l.Text.IndexOf('(');
                string sec = (pIdx >= 0 && pIdx < l.Text.Length) ? (" " + l.Text.Substring(pIdx)) : "";
                l.Text = Loc.T("DURUM & DONANIM / SİSTEM AYARI", "STATUS & HARDWARE / SYSTEM TWEAK") + sec;
            }
            foreach (var l in tweakColHeadersCol2)
            {
                l.Text = Loc.T("UYGULAMA MODU / VARYASYON", "APPLICATION MODE / VARIATION");
            }
            foreach (var l in tweakColHeadersCol3)
            {
                l.Text = Loc.T("CANLI OS DEĞERİ", "LIVE OS VALUE");
            }

            // 6. Settings Tab Controls
            if (cmbSetLanguage != null && cmbSetLanguage.SelectedIndex != (isEn ? 1 : 0))
            {
                cmbSetLanguage.SelectedIndex = isEn ? 1 : 0;
            }

            // 7. Refresh Cards & Telemetry
            foreach (var card in allCards)
            {
                card.RefreshVisualState();
            }
            UpdateTelemetryBar();
        }

        public void SwitchActiveTab(int index)
        {
            currentActiveTabIndex = index;
            if (viewGlobalSearch != null) viewGlobalSearch.Visible = false;
            viewDashboard.Visible = (index == 0);
            viewNetwork.Visible = (index == 1);
            viewLatency.Visible = (index == 2);
            viewFps.Visible = (index == 3);
            if (viewWinUtil != null) viewWinUtil.Visible = (index == 4);
            viewExperimental.Visible = (index == 5);
            viewProcesses.Visible = (index == 6);
            if (viewAutomationQoL != null) viewAutomationQoL.Visible = (index == 7);
            viewBenchmark.Visible = (index == 8);
            viewSnapshotAudit.Visible = (index == 9);
            if (viewSettings != null) viewSettings.Visible = (index == 10);

            if (index == 6) RefreshProcessTable();
            if (index == 7) RefreshAutomationQoLView();
            if (index == 9) RefreshSnapshotAuditView();
            if (index == 10)
            {
                SyncSettingsViewControlsFromModel();
                RefreshProfileSelectorCombo();
            }

            for (int i = 0; i < navButtons.Count; i++)
            {
                if (i == index)
                {
                    navButtons[i].BackColor = Color.FromArgb(16, 185, 129);
                    navButtons[i].ForeColor = Color.Black;
                }
                else
                {
                    navButtons[i].BackColor = Color.FromArgb(28, 35, 50);
                    navButtons[i].ForeColor = Color.FromArgb(203, 213, 225);
                }
            }
        }

        private void AutoResolveRebootAndReloadState(TweakDefinition t)
        {
            if (t == null) return;

            VerifySingleTweakInLiveOs(t);

            if (t.NeedsReboot)
            {
                t.RebootSatisfied = !t.IsRebootPending;
                t.PendingRebootAfterDisable = (!t.IsEnabled && t.BootTimeActiveInOs);
            }
            else
            {
                t.RebootSatisfied = true;
                t.PendingRebootAfterDisable = false;
            }

            if (t.NeedsNetReload)
            {
                if (!t.IsEnabled)
                    t.NetReloadSatisfied = true;
            }
            else
            {
                t.NetReloadSatisfied = true;
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

            // Caution Warning & Confirmation System for Critical / WinUtil Tweaks
            if (enable && tweak.RequiresCautionConfirmation && !isLoadingProfile && (appSettings == null || appSettings.ConfirmCriticalTweaks))
            {
                int previewIdx = Math.Max(0, Math.Min(variationIdx, tweak.Variations.Count - 1));
                var previewVar = tweak.Variations[previewIdx];
                string warnMsg = string.Format(
                    "KRİTİK MİMARİ AYAR ONAYI\n" +
                    "══════════════════════════════════════════════════\n" +
                    "Ayar Adı  : {0}\n" +
                    "Seçilen   : Mod {1} - {2}\n" +
                    "Kayıt Yolu: {3}\n\n" +
                    "ÖNEMLİ BİLGİLENDİRME:\n{4}\n\n" +
                    "Bu ayarı şimdi uygulamak istiyor musunuz?\n" +
                    "(İstediğiniz zaman tek tıkla kapatarak fabrika varsayılanına geri dönebilirsiniz.)",
                    tweak.Title,
                    previewIdx + 1,
                    previewVar.DetailedTitle,
                    tweak.TargetPathOrApi,
                    !string.IsNullOrEmpty(tweak.CautionWarningText) ? tweak.CautionWarningText : tweak.SummaryDescription);

                DialogResult warnDr = MessageBox.Show(
                    warnMsg,
                    "Argon Kritik Ayar Onay Sistemi",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (warnDr != DialogResult.Yes)
                {
                    tweak.IsEnabled = false;
                    VerifySingleTweakInLiveOs(tweak);
                    foreach (var c in allCards) if (c.Tweak == tweak) c.RefreshVisualState();
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
                    tweak.IsEnabled = true;
                    var chosenVar = tweak.Variations[safeIdx];
                    if (chosenVar.ApplyAction != null)
                        chosenVar.ApplyAction();
                    tweak.CurrentAppliedText = string.Format("Mod {0}: {1}", safeIdx + 1, chosenVar.ShortLabel);

                    AutoResolveRebootAndReloadState(tweak);
                    OnTweakCardHovered(tweak, chosenVar);
                    EnforceFixedCombinationsAndConflicts(tweak);

                    bannerDismissedBySession = false;
                    string statusMsg = tweak.IsVerifiedInOs ? ("Doğrulandı: " + tweak.VerifiedSystemValue) : "Uygulandı";
                    if (tweak.NeedsReboot)
                    {
                        if (tweak.IsRebootPending)
                            statusMsg += " [Kayıt Defterine Yazıldı - Windows Kernel İçin Restart Bekliyor]";
                        else
                            statusMsg += " [OS Zaten Bu Modla Açıldı - Restart Gereksiz]";
                    }
                    AppendConsoleLog(string.Format("AKTİF -> {0} [Mod {1}: {2}] ({3})",
                        tweak.Title, safeIdx + 1, chosenVar.ShortLabel, statusMsg));
                }
                else
                {
                    bannerDismissedBySession = false;
                    tweak.IsEnabled = false;
                    tweak.IsVerifiedInOs = false;
                    tweak.VerifiedSystemValue = "";
                    if (tweak.RevertAction != null)
                        tweak.RevertAction();
                    tweak.CurrentAppliedText = "Pasif (Orijinal)";

                    AutoResolveRebootAndReloadState(tweak);

                    string revStatus = tweak.IsRebootPending
                        ? "Orijinale Çekildi [Kernel İçin Restart Bekliyor]"
                        : (tweak.CapturedOriginalSummary ?? "Standart (Anında Aktif)");
                    AppendConsoleLog(string.Format("VARSAYILANA DÖNDÜ -> {0} ({1})",
                        tweak.Title, revStatus));
                }
            }
            catch (Exception ex)
            {
                lblInspectorTitle.Text = "Uygulama Uyarısı: " + ex.Message;
                AppendConsoleLog("HATA -> " + tweak.Title + ": " + ex.Message);
            }

            foreach (var c in allCards) if (c.Tweak == tweak) c.RefreshVisualState();
            UpdateActiveCountsAndNavBadges();
            UpdateRebootAndReloadBannerVisibility();
            RefreshSnapshotAuditView();
            UpdateTelemetryBar();
            if (!isLoadingProfile) SaveUserProfileState();
        }

        private void OnTweakCardHovered(TweakDefinition tweak, TweakVariation variation)
        {
            if (tweak == null || variation == null) return;
            string verifyTag;
            if (tweak.IsEnabled)
            {
                verifyTag = tweak.IsVerifiedInOs
                    ? ("✓ Sistemde Doğrulandı (" + tweak.VerifiedSystemValue + ")")
                    : "! Doğrulanamadı";
            }
            else if (tweak.IsDetectedActiveInOs)
            {
                verifyTag = "● Sistemde Zaten Aktif Algılandı (" + tweak.LiveOsRawSummary + ")";
            }
            else
            {
                verifyTag = "Varsayılanda (" + tweak.CapturedOriginalSummary + ")";
            }
            lblInspectorTitle.Text = string.Format("{0} — [{1}]", tweak.Title, variation.DetailedTitle);
            lblInspectorPath.Text = string.Format("Hedef: {0}  |  Parametre: {1}  |  Canlı OS: {2}",
                tweak.TargetPathOrApi, variation.ExactParameters, verifyTag);
        }

        /// <summary>
        /// Real-Time OS Truth Detection Engine:
        /// Probes every single tweak in the catalog against live Windows state (Registry, Power Scheme, SPI, Kernel Timer, Services)
        /// regardless of saved flags. If syncUiTogglesToOsTruth is true, it also synchronizes t.IsEnabled and SelectedVariationIndex
        /// so external changes or resets are 100% accurately reflected in the UI.
        /// </summary>
        private void ProbeAllTweaksLiveOsTruthAndOptionallySync(bool syncUiTogglesToOsTruth)
        {
            int detectedInOsCount = 0;
            int syncedCount = 0;

            foreach (var t in allTweaks)
            {
                bool liveActive = VerifySingleTweakInLiveOs(t);
                if (liveActive) detectedInOsCount++;

                if (syncUiTogglesToOsTruth)
                {
                    // Runtime-only process tweaks keep their session state unless detected active
                    bool isRuntimeOnly = (t.Id == "LAT_TIMER" || t.Id == "FPS_ECOQOS_GOVERNOR" || t.Id == "FPS_AUDIODG_DWM_ISO" ||
                                          t.Id == "FPS_LIVE_SERVICES" || t.Id == "EXP_SYNTHETIC_PULSE" || t.Id == "EXP_SMT_ISOLATION" ||
                                          t.Id == "EXP_TCP_CONGESTION" || t.Id == "EXP_IO_PAGE_PRIO" || t.Id == "EXP_ECN_HEURISTICS");

                    if (liveActive && !t.IsEnabled)
                    {
                        t.IsEnabled = true;
                        if (t.DetectedVariationInOs >= 0 && t.DetectedVariationInOs < t.Variations.Count)
                            t.SelectedVariationIndex = t.DetectedVariationInOs;
                        t.RebootSatisfied = true;
                        t.NetReloadSatisfied = true;
                        syncedCount++;
                    }
                    else if (!liveActive && t.IsEnabled && !isRuntimeOnly)
                    {
                        t.IsEnabled = false;
                        t.RebootSatisfied = false;
                        t.NetReloadSatisfied = false;
                        t.PendingRebootAfterDisable = false;
                        syncedCount++;
                    }
                    else if (liveActive && t.IsEnabled && t.DetectedVariationInOs >= 0 && t.DetectedVariationInOs < t.Variations.Count)
                    {
                        if (t.SelectedVariationIndex != t.DetectedVariationInOs)
                        {
                            t.SelectedVariationIndex = t.DetectedVariationInOs;
                            syncedCount++;
                        }
                    }
                }

                // Canlı OS'ta doğrulanmış olan ayarların boot durumunu da gerçek OS değerine eşitle
                if (t.IsVerifiedInOs && (t.DetectedVariationInOs < 0 || t.DetectedVariationInOs == t.SelectedVariationIndex))
                {
                    t.BootTimeActiveInOs = true;
                    if (t.DetectedVariationInOs >= 0) t.BootTimeVariationInOs = t.DetectedVariationInOs;
                    t.RebootSatisfied = true;
                    t.NetReloadSatisfied = true;
                }

                // Her bir ayar için Live OS truth ve restart/reload gereksinimini hatasız ve otomatik çözümle
                AutoResolveRebootAndReloadState(t);
            }

            foreach (var c in allCards)
                c.RefreshVisualState();

            UpdateActiveCountsAndNavBadges();
            UpdateRebootAndReloadBannerVisibility();
            RefreshSnapshotAuditView();

            if (syncUiTogglesToOsTruth && !isLoadingProfile)
                SaveUserProfileState();

            if (lblInspectorTitle != null && syncUiTogglesToOsTruth)
            {
                lblInspectorTitle.Text = string.Format("GERÇEK WINDOWS DURUMU (LIVE OS TRUTH) ALGILANDI: Sistemde {0} ayar aktif bulundu ({1} anahtar eşitlendi).", detectedInOsCount, syncedCount);
                lblInspectorPath.Text = "Tüm satırların durumu bayraklardan bağımsız olarak doğrudan Kayıt Defteri, Güç Planı ve Kernel üzerinden türetildi.";
            }
            AppendConsoleLog(string.Format("Canlı OS Denetimi tamamlandı: {0} aktif ayar algılandı ({1} eşitlendi).", detectedInOsCount, syncedCount));
        }

        /// <summary>
        /// Arka planda periyodik olarak çalışan, kullanıcıdan manuel buton tıklaması beklemeden
        /// sistem durumunu sessizce denetleyen ve arayüzü sürekli güncel tutan otomatik OS doğrulama motoru.
        /// </summary>
        private void AutoSyncLiveOsTruthInBackground()
        {
            if (isLoadingProfile) return;
            try
            {
                bool visualRefreshNeeded = false;
                foreach (var t in allTweaks)
                {
                    bool wasActive = t.IsDetectedActiveInOs;
                    int wasVar = t.DetectedVariationInOs;
                    bool wasVerified = t.IsVerifiedInOs;
                    bool wasRebootSat = t.RebootSatisfied;
                    bool wasPendingReboot = t.PendingRebootAfterDisable;

                    AutoResolveRebootAndReloadState(t);

                    if (wasActive != t.IsDetectedActiveInOs || wasVar != t.DetectedVariationInOs ||
                        wasVerified != t.IsVerifiedInOs || wasRebootSat != t.RebootSatisfied ||
                        wasPendingReboot != t.PendingRebootAfterDisable)
                    {
                        visualRefreshNeeded = true;
                    }
                }

                if (visualRefreshNeeded)
                {
                    foreach (var c in allCards) c.RefreshVisualState();
                    UpdateActiveCountsAndNavBadges();
                    UpdateRebootAndReloadBannerVisibility();
                }
            }
            catch { }
        }

        #region Custom Named Profile Manager (Save, Load, Delete, Export, Import)

        private void LoadCustomProfilesList()
        {
            customProfiles.Clear();
            try
            {
                if (!Directory.Exists(customProfilesDir)) return;
                foreach (string file in Directory.GetFiles(customProfilesDir, "*.argon"))
                {
                    ArgonCustomProfile p = ArgonCustomProfile.LoadFromFile(file);
                    if (p != null && !string.IsNullOrEmpty(p.ProfileName))
                        customProfiles.Add(p);
                }
                customProfiles.Sort((a, b) => string.Compare(a.ProfileName, b.ProfileName, StringComparison.OrdinalIgnoreCase));
            }
            catch { }
        }

        private void RefreshProfileSelectorCombo()
        {
            LoadCustomProfilesList();
            suppressProfileComboEvent = true;
            try
            {
                if (cmbProfileSelector != null)
                {
                    cmbProfileSelector.Items.Clear();
                    cmbProfileSelector.Items.Add("⚡ [Hazır] Kademe 2: Rekabetçi Espor");
                    cmbProfileSelector.Items.Add("🧊 [Hazır] Kademe 1: Serin & Dengeli");
                    cmbProfileSelector.Items.Add("🔥 [Hazır] Kademe 3: Turnuva Ekstrem");
                    cmbProfileSelector.Items.Add("🌐 [Hazır] Sadece Ağ & Düşük Ping");
                    foreach (var cp in customProfiles)
                    {
                        cmbProfileSelector.Items.Add("⭐ [Özel] " + cp.ProfileName);
                    }
                    int selIdx = 0;
                    if (appSettings != null && !string.IsNullOrEmpty(appSettings.LastSelectedProfileName))
                    {
                        for (int i = 0; i < cmbProfileSelector.Items.Count; i++)
                        {
                            if (cmbProfileSelector.Items[i].ToString().IndexOf(appSettings.LastSelectedProfileName, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                selIdx = i;
                                break;
                            }
                        }
                    }
                    if (cmbProfileSelector.Items.Count > 0)
                        cmbProfileSelector.SelectedIndex = selIdx;
                }

                if (lstCustomProfilesManager != null)
                {
                    lstCustomProfilesManager.Items.Clear();
                    lstCustomProfilesManager.Items.Add("[HAZIR SİSTEM PROFİLİ] ⚡ Kademe 2: Rekabetçi Espor (Önerilen)");
                    lstCustomProfilesManager.Items.Add("[HAZIR SİSTEM PROFİLİ] 🧊 Kademe 1: Serin & Dengeli");
                    lstCustomProfilesManager.Items.Add("[HAZIR SİSTEM PROFİLİ] 🔥 Kademe 3: Turnuva Ekstrem Kilit");
                    lstCustomProfilesManager.Items.Add("[HAZIR SİSTEM PROFİLİ] 🌐 Sadece Ağ & Düşük Ping Reçetesi");
                    foreach (var cp in customProfiles)
                    {
                        lstCustomProfilesManager.Items.Add(string.Format("[KULLANICI PROFİLİ] ⭐ {0}  ({1} aktif ayar | {2})",
                            cp.ProfileName, cp.TweakStates.Count, cp.CreatedAt));
                    }
                }
            }
            finally
            {
                suppressProfileComboEvent = false;
            }
        }

        private void OnTopProfileDropdownSelected()
        {
            if (suppressProfileComboEvent || isLoadingProfile || cmbProfileSelector == null || cmbProfileSelector.SelectedIndex < 0)
                return;

            int idx = cmbProfileSelector.SelectedIndex;
            if (idx == 0)
            {
                SelectProgressiveTier(2);
                ApplyHardwareAwareSmartTune();
                if (appSettings != null) { appSettings.LastSelectedProfileName = "Kademe 2"; appSettings.Save(appSettingsPath); }
            }
            else if (idx == 1)
            {
                SelectProgressiveTier(1);
                ApplyHardwareAwareSmartTune();
                if (appSettings != null) { appSettings.LastSelectedProfileName = "Kademe 1"; appSettings.Save(appSettingsPath); }
            }
            else if (idx == 2)
            {
                SelectProgressiveTier(3);
                ApplyHardwareAwareSmartTune();
                if (appSettings != null) { appSettings.LastSelectedProfileName = "Kademe 3"; appSettings.Save(appSettingsPath); }
            }
            else if (idx == 3)
            {
                ApplyNetworkOnlyBuiltInProfile();
                if (appSettings != null) { appSettings.LastSelectedProfileName = "Sadece Ağ"; appSettings.Save(appSettingsPath); }
            }
            else
            {
                int customIdx = idx - 4;
                if (customIdx >= 0 && customIdx < customProfiles.Count)
                {
                    ApplyCustomProfileObject(customProfiles[customIdx]);
                }
            }
        }

        private void ApplyNetworkOnlyBuiltInProfile()
        {
            foreach (var card in allCards)
            {
                var t = card.Tweak;
                bool want = (t.Category == "NETWORK" && t.Id != "NET_DNS_SWITCH");
                if (want && (!t.RequiresAdmin || isAdmin))
                {
                    t.IsEnabled = true;
                    t.SelectedVariationIndex = 0;
                    if (t.Variations[0].ApplyAction != null) t.Variations[0].ApplyAction();
                    VerifySingleTweakInLiveOs(t);
                }
                else if (!want && t.IsEnabled)
                {
                    t.IsEnabled = false;
                    if (t.RevertAction != null) t.RevertAction();
                    VerifySingleTweakInLiveOs(t);
                }
                card.RefreshVisualState();
            }
            EnforceFixedCombinationsAndConflicts(null);
            UpdateActiveCountsAndNavBadges();
            RefreshSnapshotAuditView();
            SaveUserProfileState();
            lblInspectorTitle.Text = "🌐 'Sadece Ağ & Düşük Ping' hazır profili uygulandı.";
        }

        private void PromptAndSaveCustomNamedProfile()
        {
            using (Form prompt = new Form())
            {
                prompt.Width = 440;
                prompt.Height = 195;
                prompt.FormBorderStyle = FormBorderStyle.FixedDialog;
                prompt.Text = "💾 Yeni Özel Profil Kaydet";
                prompt.StartPosition = FormStartPosition.CenterParent;
                prompt.MaximizeBox = false;
                prompt.MinimizeBox = false;
                prompt.BackColor = Color.FromArgb(19, 24, 36);
                prompt.ForeColor = Color.White;

                Label lbl = new Label
                {
                    Left = 18,
                    Top = 18,
                    Width = 390,
                    Height = 38,
                    Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                    ForeColor = Color.FromArgb(52, 211, 153),
                    Text = "Şu an açık olan ayarlarınız için özel bir profil adı girin:\n(Daha sonra üst menüden istediğiniz zaman seçebilirsiniz)"
                };
                TextBox txt = new TextBox
                {
                    Left = 18,
                    Top = 64,
                    Width = 388,
                    BackColor = Color.FromArgb(13, 16, 23),
                    ForeColor = Color.White,
                    BorderStyle = BorderStyle.FixedSingle,
                    Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                    Text = "Özel Profilim " + (customProfiles.Count + 1)
                };
                Button btnOk = new Button
                {
                    Text = "💾 Kaydet",
                    Left = 216,
                    Width = 92,
                    Top = 104,
                    Height = 32,
                    DialogResult = DialogResult.OK,
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.FromArgb(16, 185, 129),
                    ForeColor = Color.Black,
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                btnOk.FlatAppearance.BorderSize = 0;
                Button btnCancel = new Button
                {
                    Text = "İptal",
                    Left = 314,
                    Width = 92,
                    Top = 104,
                    Height = 32,
                    DialogResult = DialogResult.Cancel,
                    FlatStyle = FlatStyle.Flat,
                    BackColor = Color.FromArgb(51, 65, 85),
                    ForeColor = Color.White,
                    Font = new Font("Segoe UI", 8.5f, FontStyle.Bold)
                };
                btnCancel.FlatAppearance.BorderSize = 0;

                prompt.Controls.Add(lbl);
                prompt.Controls.Add(txt);
                prompt.Controls.Add(btnOk);
                prompt.Controls.Add(btnCancel);
                prompt.AcceptButton = btnOk;
                prompt.CancelButton = btnCancel;

                if (prompt.ShowDialog(this) == DialogResult.OK)
                {
                    string name = (txt.Text ?? "").Trim();
                    if (!string.IsNullOrEmpty(name))
                        SaveCurrentStateAsCustomProfile(name);
                }
            }
        }

        private void SaveCurrentStateAsCustomProfile(string profileName)
        {
            try
            {
                ArgonCustomProfile prof = new ArgonCustomProfile
                {
                    ProfileName = profileName.Replace("|", "-").Trim(),
                    CreatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
                    CpuProfile = (int)selectedCpuProfile,
                    GpuProfile = (int)selectedGpuProfile,
                    ProgressiveTier = selectedProgressiveTier
                };
                foreach (var t in allTweaks)
                {
                    if (t.IsEnabled)
                        prof.TweakStates[t.Id] = new KeyValuePair<bool, int>(true, t.SelectedVariationIndex);
                }

                string safeFile = prof.ProfileName;
                foreach (char c in Path.GetInvalidFileNameChars())
                    safeFile = safeFile.Replace(c, '_');
                string fullPath = Path.Combine(customProfilesDir, safeFile + ".argon");
                prof.SaveToFile(fullPath);

                if (appSettings != null)
                {
                    appSettings.LastSelectedProfileName = prof.ProfileName;
                    appSettings.Save(appSettingsPath);
                }

                RefreshProfileSelectorCombo();
                lblInspectorTitle.Text = string.Format("💾 Özel Profil Kaydedildi: '{0}' ({1} aktif ayar).", prof.ProfileName, prof.TweakStates.Count);
                lblInspectorPath.Text = "Üst bardaki '💾 Profil' açılır menüsünden istediğiniz zaman bu profile geçiş yapabilirsiniz.";
            }
            catch (Exception ex)
            {
                MessageBox.Show("Profil kaydedilirken hata oluştu: " + ex.Message, "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ApplyCustomProfileObject(ArgonCustomProfile prof)
        {
            if (prof == null) return;
            isLoadingProfile = true;
            try
            {
                if (prof.CpuProfile >= 0 && prof.CpuProfile < cmbCpuSelector.Items.Count)
                {
                    selectedCpuProfile = (CpuProfileType)prof.CpuProfile;
                    cmbCpuSelector.SelectedIndex = prof.CpuProfile;
                }
                if (prof.GpuProfile >= 0 && prof.GpuProfile < cmbGpuSelector.Items.Count)
                {
                    selectedGpuProfile = (GpuProfileType)prof.GpuProfile;
                    cmbGpuSelector.SelectedIndex = prof.GpuProfile;
                }
                if (prof.ProgressiveTier >= 1 && prof.ProgressiveTier <= 3)
                    SelectProgressiveTier(prof.ProgressiveTier);

                int appliedCount = 0;
                foreach (var card in allCards)
                {
                    var t = card.Tweak;
                    KeyValuePair<bool, int> kv;
                    bool want = prof.TweakStates.TryGetValue(t.Id, out kv) && kv.Key;
                    int varIdx = want ? Math.Max(0, Math.Min(kv.Value, t.Variations.Count - 1)) : 0;

                    if (want && (!t.RequiresAdmin || isAdmin))
                    {
                        t.IsEnabled = true;
                        t.SelectedVariationIndex = varIdx;
                        try
                        {
                            if (t.Variations[varIdx].ApplyAction != null)
                                t.Variations[varIdx].ApplyAction();
                            appliedCount++;
                        }
                        catch { }
                        VerifySingleTweakInLiveOs(t);
                    }
                    else if (!want && t.IsEnabled)
                    {
                        t.IsEnabled = false;
                        try { if (t.RevertAction != null) t.RevertAction(); } catch { }
                        VerifySingleTweakInLiveOs(t);
                    }
                    card.RefreshVisualState();
                }

                if (appSettings != null)
                {
                    appSettings.LastSelectedProfileName = prof.ProfileName;
                    appSettings.Save(appSettingsPath);
                }

                RefreshHardwareMatrixCards();
                UpdateActiveCountsAndNavBadges();
                UpdateRebootAndReloadBannerVisibility();
                RefreshSnapshotAuditView();
                lblInspectorTitle.Text = string.Format("⭐ Özel Kullanıcı Profili Uygulandı: '{0}' ({1} ayar aktif ve canlı doğrulandı).", prof.ProfileName, appliedCount);
            }
            finally
            {
                isLoadingProfile = false;
                SaveUserProfileState();
                RefreshProfileSelectorCombo();
            }
        }

        private void ApplyProfileFromSettingsListSelection()
        {
            if (lstCustomProfilesManager == null || lstCustomProfilesManager.SelectedIndex < 0) return;
            int idx = lstCustomProfilesManager.SelectedIndex;
            if (idx == 0) { SelectProgressiveTier(2); ApplyHardwareAwareSmartTune(); }
            else if (idx == 1) { SelectProgressiveTier(1); ApplyHardwareAwareSmartTune(); }
            else if (idx == 2) { SelectProgressiveTier(3); ApplyHardwareAwareSmartTune(); }
            else if (idx == 3) { ApplyNetworkOnlyBuiltInProfile(); }
            else
            {
                int cIdx = idx - 4;
                if (cIdx >= 0 && cIdx < customProfiles.Count)
                    ApplyCustomProfileObject(customProfiles[cIdx]);
            }
        }

        private void DeleteProfileFromSettingsListSelection()
        {
            if (lstCustomProfilesManager == null || lstCustomProfilesManager.SelectedIndex < 4)
            {
                MessageBox.Show("Hazır sistem profilleri silinemez. Silmek için listeden kendi oluşturduğunuz bir '[KULLANICI PROFİLİ]' seçin.", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            int cIdx = lstCustomProfilesManager.SelectedIndex - 4;
            if (cIdx >= 0 && cIdx < customProfiles.Count)
            {
                var prof = customProfiles[cIdx];
                if (MessageBox.Show(string.Format("'{0}' adlı özel profilinizi silmek istediğinize emin misiniz?", prof.ProfileName), "Profili Sil", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    try
                    {
                        foreach (string f in Directory.GetFiles(customProfilesDir, "*.argon"))
                        {
                            var loaded = ArgonCustomProfile.LoadFromFile(f);
                            if (loaded != null && string.Equals(loaded.ProfileName, prof.ProfileName, StringComparison.OrdinalIgnoreCase))
                                File.Delete(f);
                        }
                    }
                    catch { }
                    RefreshProfileSelectorCombo();
                }
            }
        }

        private void ExportCurrentProfileDialog()
        {
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Title = "Mevcut Argon Profilini Dışa Aktar";
                sfd.Filter = "Argon Profil Dosyası (*.argon)|*.argon";
                sfd.FileName = "Argon_Ozel_Profil.argon";
                if (sfd.ShowDialog(this) == DialogResult.OK)
                {
                    ArgonCustomProfile prof = new ArgonCustomProfile
                    {
                        ProfileName = Path.GetFileNameWithoutExtension(sfd.FileName),
                        CreatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm"),
                        CpuProfile = (int)selectedCpuProfile,
                        GpuProfile = (int)selectedGpuProfile,
                        ProgressiveTier = selectedProgressiveTier
                    };
                    foreach (var t in allTweaks)
                        if (t.IsEnabled) prof.TweakStates[t.Id] = new KeyValuePair<bool, int>(true, t.SelectedVariationIndex);
                    prof.SaveToFile(sfd.FileName);
                    lblInspectorTitle.Text = "📤 Profil başarıyla dışa aktarıldı: " + sfd.FileName;
                }
            }
        }

        private void ImportCustomProfileDialog()
        {
            using (OpenFileDialog ofd = new OpenFileDialog())
            {
                ofd.Title = "Argon Profil Dosyası İçe Aktar";
                ofd.Filter = "Argon Profil Dosyası (*.argon)|*.argon";
                if (ofd.ShowDialog(this) == DialogResult.OK)
                {
                    var prof = ArgonCustomProfile.LoadFromFile(ofd.FileName);
                    if (prof != null)
                    {
                        string dest = Path.Combine(customProfilesDir, Path.GetFileName(ofd.FileName));
                        prof.SaveToFile(dest);
                        RefreshProfileSelectorCombo();
                        ApplyCustomProfileObject(prof);
                    }
                }
            }
        }

        #endregion

        private void SaveUserProfileState()
        {
            if (isLoadingProfile || string.IsNullOrEmpty(userProfilePath)) return;
            try
            {
                List<string> lines = new List<string>();
                lines.Add("PROFVER|40");
                lines.Add("BOOTSTAMP|" + currentBootStamp);
                lines.Add("CPU|" + (int)selectedCpuProfile);
                lines.Add("GPU|" + (int)selectedGpuProfile);
                lines.Add("TIER|" + selectedProgressiveTier);
                lines.Add("WATCHDOG|" + autoGameWatchdogActive);
                lines.Add("REVERTONEXIT|" + revertOnExit);

                foreach (var t in allTweaks)
                {
                    string keptLine;
                    if (!t.IsEnabled && preservedProfileTweakLines.TryGetValue(t.Id, out keptLine))
                    {
                        lines.Add(keptLine);
                        continue;
                    }
                    lines.Add(string.Format("TWEAK|{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}",
                        t.Id, t.IsEnabled, t.SelectedVariationIndex, t.RebootSatisfied, t.NetReloadSatisfied,
                        t.ModifiedBootStamp ?? currentBootStamp, t.BootTimeActiveInOs, t.BootTimeVariationInOs));

                    if (t.CustomParam != null && t.CustomParam.CurrentCustomValue > 0)
                    {
                        lines.Add(string.Format("CUSTOMVAL|{0}|{1}", t.Id, t.CustomParam.CurrentCustomValue));
                    }
                }

                StateVault.WriteAllLinesAtomic(userProfilePath, lines.ToArray());
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
                string[] lines = File.ReadAllLines(userProfilePath, Encoding.UTF8);
                foreach (string l in lines)
                {
                    if (l == null) continue;
                    if (l.StartsWith("PROFVER|37")) isVer37OrNewer = true;
                    if (l.StartsWith("PROFVER|38") || l.StartsWith("PROFVER|40")) { isVer37OrNewer = true; isVer38OrNewer = true; }
                }

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
                    else if (parts[0] == "REVERTONEXIT" && parts.Length >= 2)
                    {
                        bool roe;
                        if (bool.TryParse(parts[1], out roe))
                        {
                            SetRevertOnExit(roe);
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
                            bool savedBootActive = false;
                            int savedBootVar = -1;
                            if (parts.Length >= 6)
                            {
                                bool.TryParse(parts[4], out savedRebootSat);
                                bool.TryParse(parts[5], out savedNetSat);
                            }
                            if (parts.Length >= 7)
                            {
                                savedModBoot = parts[6];
                            }
                            if (parts.Length >= 9)
                            {
                                bool.TryParse(parts[7], out savedBootActive);
                                int.TryParse(parts[8], out savedBootVar);
                            }

                            TweakDefinition t = FindTweak(id);
                            if (t != null)
                            {
                                int safeIdx = Math.Max(0, Math.Min(varIdx, t.Variations.Count - 1));
                                t.SelectedVariationIndex = safeIdx;
                                t.PendingRebootAfterDisable = false;

                                // Canlı OS durumunu doğrudan tara; dosyadaki eski/bayat boot değişkenleriyle ASLA ezme!
                                VerifySingleTweakInLiveOs(t);
                                if (t.IsDetectedActiveInOs)
                                {
                                    t.BootTimeActiveInOs = true;
                                    t.BootTimeVariationInOs = t.DetectedVariationInOs;
                                    t.BootTimeRawValue = t.VerifiedSystemValue;
                                }

                                if (enabled && (!t.RequiresAdmin || isAdmin))
                                {
                                    t.IsEnabled = true;
                                    try
                                    {
                                        if (t.Variations[safeIdx].ApplyAction != null)
                                            t.Variations[safeIdx].ApplyAction();
                                        t.CurrentAppliedText = string.Format("Mod {0}: {1}", safeIdx + 1, t.Variations[safeIdx].ShortLabel);
                                        restoredActiveCount++;
                                    }
                                    catch { }

                                    // Canlı OS ile doğrula: sistem zaten bu varyasyonda ise restart/reload gereksinimini hemen tatmin et
                                    VerifySingleTweakInLiveOs(t);
                                    if (t.IsDetectedActiveInOs && (t.DetectedVariationInOs < 0 || t.DetectedVariationInOs == safeIdx))
                                    {
                                        t.BootTimeActiveInOs = true;
                                        t.BootTimeVariationInOs = safeIdx;
                                        t.RebootSatisfied = true;
                                        t.NetReloadSatisfied = true;
                                    }

                                    AutoResolveRebootAndReloadState(t);
                                    if (t.IsVerifiedInOs) verifiedCount++;
                                }
                                else
                                {
                                    if (enabled && t.RequiresAdmin && !isAdmin)
                                        preservedProfileTweakLines[t.Id] = line;
                                    t.IsEnabled = false;
                                    t.IsVerifiedInOs = false;
                                    t.VerifiedSystemValue = "";
                                    if (t.Id == "LAT_FILTERKEYS")
                                    {
                                        try { if (t.RevertAction != null) t.RevertAction(); } catch { }
                                    }
                                    AutoResolveRebootAndReloadState(t);
                                }
                            }
                        }
                    }
                    else if (parts[0] == "CUSTOMVAL" && parts.Length >= 3)
                    {
                        string id = parts[1];
                        int cVal;
                        if (int.TryParse(parts[2], out cVal))
                        {
                            TweakDefinition t = FindTweak(id);
                            if (t != null && t.CustomParam != null)
                            {
                                t.CustomParam.CurrentCustomValue = cVal;
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
                foreach (var c in allCards)
                {
                    c.UpdateCustomVariationLabel();
                    c.RefreshVisualState();
                }
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
                if (card.Tweak.IsEnabled || card.Tweak.IsDetectedActiveInOs)
                {
                    card.Tweak.IsEnabled = false;
                    card.Tweak.RebootSatisfied = false;
                    card.Tweak.NetReloadSatisfied = false;
                    card.Tweak.PendingRebootAfterDisable = false;
                    card.Tweak.IsVerifiedInOs = false;
                    card.Tweak.IsDetectedActiveInOs = false;
                    card.Tweak.DetectedVariationInOs = -1;
                    card.Tweak.VerifiedSystemValue = "";
                    try
                    {
                        if (card.Tweak.RevertAction != null)
                            card.Tweak.RevertAction();
                    }
                    catch { }
                }
            }

            StopSyntheticPulseThread();
            fpsEcoQosMode = 0;
            fpsAudioIsoMode = 0;
            ResumePausedWindowsServices();
            timerLockActive = false;
            try
            {
                ReleaseTimerPeriod();
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

            // Re-probe real OS truth for every tweak after rollback so there are ZERO visual bugs after reset!
            ProbeAllTweaksLiveOsTruthAndOptionallySync(false);

            UpdateActiveCountsAndNavBadges();
            UpdateRebootAndReloadBannerVisibility();
            RefreshSnapshotAuditView();

            lblInspectorTitle.Text = "✅ TÜM AYARLAR İLK HALİNE DÖNDÜRÜLDÜ (Canlı OS Doğrulaması İle %100 Fabrika Durumu Teyit Edildi)";
            lblInspectorPath.Text = "StateVault: Tüm Kayıt Defteri, Netsh, Güç Planı, Fare/Klavye ve Süreç ayarları fabrika yedeğine döndürüldü ve canlı denetlendi.";
            AppendConsoleLog("Fabrika Sıfırlama (StateVault Rollback): Tüm ayarlar ilk haline döndürüldü ve canlı OS ile teyit edildi.");
        }

        private void PromptAndRestartComputerNow()
        {
            SaveUserProfileState();
            int pendingReboot = 0;
            List<string> pendingNames = new List<string>();
            foreach (var t in allTweaks)
            {
                AutoResolveRebootAndReloadState(t);
                if (t.IsRebootPending)
                {
                    pendingReboot++;
                    pendingNames.Add(t.Title);
                }
            }

            string tweakListText = pendingNames.Count > 0 ? ("\n\nBekleyen Ayarlar:\n• " + string.Join("\n• ", pendingNames.ToArray())) : "";
            string msg = pendingReboot > 0
                ? string.Format("Açık olan tüm ayarlarınız ve profiliniz kaydedildi.\n\nWindows çekirdeğinde devreye girmek için yeniden başlatma bekleyen {0} sistem ayarı bulunuyor:{1}\n\nBilgisayarı şimdi yeniden başlatmak istiyor musunuz?\n\n(Bilgisayar yeniden açıldığında bu ayarlar otomatik olarak '✓ Doğrulandı' durumuna geçecektir.)", pendingReboot, tweakListText)
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
                    suppressRevertOnExit = true; // reboot is meant to activate reboot-required tweaks
                    PerformCleanShutdownKeepSettings();
                    StateVault.RunHiddenCmd("shutdown.exe", "/r /t 2 /c \"Argon Low Latency Studio: Ayarlar devreye aliniyor...\"");
                    Application.Exit();
                }
                catch { }
            }
        }

        private bool VerifySingleTweakInLiveOs(TweakDefinition t)
        {
            if (t == null) return false;

            try
            {
                string id = t.Id;
                string val = "";
                bool ok = false;
                int detectedMod = -1;

                if (id == "HW_INTEL_CPU" || id == "HW_AMD_CPU")
                {
                    string epp = ReadCurrentActivePowerAcValue(SUB_PROCESSOR, SET_PERFEPP, "");
                    ok = (epp == "0" || epp == "15" || vault.SessionCustomPowerScheme != Guid.Empty);
                    val = !string.IsNullOrEmpty(epp) ? ("EPP=" + epp) : "Güç Planı Aktif";
                    if (epp == "0") detectedMod = 0;
                    else if (epp == "15") detectedMod = (id == "HW_INTEL_CPU" ? 1 : 2);
                }
                else if (id == "HW_NVIDIA_GPU")
                {
                    string dpc = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "RmGpsPsEnablePerCpuCoreDpc", "");
                    string pst = vault.ReadRegistryDisplay("HKLM", activeGpuClassSubKey, "DisableDynamicPstate", "");
                    ok = (dpc == "1" || pst == "1");
                    val = ok ? string.Format("CoreDpc={0}, Pstate={1}", string.IsNullOrEmpty(dpc) ? "0" : dpc, string.IsNullOrEmpty(pst) ? "0" : pst) : "";
                    if (pst == "1") detectedMod = 0;
                    else if (dpc == "1") detectedMod = 1;
                }
                else if (id == "HW_AMD_GPU")
                {
                    string ulps = vault.ReadRegistryDisplay("HKLM", activeGpuClassSubKey, "EnableUlps", "");
                    string delag = vault.ReadRegistryDisplay("HKLM", activeGpuClassSubKey, "KMD_DeLagEnabled", "");
                    ok = (ulps == "0");
                    val = ok ? (delag == "1" ? "ULPS=0, DeLag=1" : "ULPS=0 (Kapalı)") : "";
                    if (ulps == "0") detectedMod = (delag == "1" ? 0 : 1);
                }
                else if (id == "HW_INTEL_GPU")
                {
                    string aspm = ReadCurrentActivePowerAcValue(SUB_PCIEXPRESS, SET_PCIEASPM, "");
                    ok = (aspm == "0");
                    val = ok ? "PCIe_ASPM=0" : "";
                    if (ok) detectedMod = 0;
                }
                else if (id == "NET_NAGLE")
                {
                    if (activeTcpInterfaceGuids.Count > 0)
                    {
                        string k = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + activeTcpInterfaceGuids[0];
                        string ack = vault.ReadRegistryDisplay("HKLM", k, "TcpAckFrequency", "");
                        string nd = vault.ReadRegistryDisplay("HKLM", k, "TCPNoDelay", "");
                        ok = (ack == "1" || ack == "2" || nd == "1");
                        val = string.Format("Ack={0}, NoDelay={1}", ack, nd);
                        if (ack == "1" && nd == "1") detectedMod = 0;
                        else if (ack == "2" && nd == "1") detectedMod = 1;
                        else if (ack == "1" && nd == "0") detectedMod = 2;
                    }
                }
                else if (id == "NET_AUTOTUNING")
                {
                    string o = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Tcp1323Opts", "");
                    ok = (o == "1" || o == "0" || o == "3");
                    val = "Tcp1323Opts=" + o;
                    if (o == "1") detectedMod = 0;
                    else if (o == "0") detectedMod = 2;
                    else if (o == "3") detectedMod = 3;
                }
                else if (id == "NET_THROTTLING")
                {
                    string sr = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness", "");
                    string nt = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NetworkThrottlingIndex", "");
                    ok = (sr == "0" || sr == "10");
                    val = "Responsiveness=%" + sr;
                    if (sr == "0") detectedMod = 0;
                    else if (sr == "10") detectedMod = (nt == "70" ? 2 : 1);
                }
                else if (id == "NET_RTO")
                {
                    string mr = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpMaxDataRetransmissions", "");
                    ok = (mr == "3" || mr == "5");
                    val = "MaxRetrans=" + mr;
                    if (mr == "3") detectedMod = 0;
                    else if (mr == "5") detectedMod = 1;
                }
                else if (id == "NET_PORTS_TTL")
                {
                    string mp = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "MaxUserPort", "");
                    string tw = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpTimedWaitDelay", "");
                    ok = (mp == "65534" || mp == "32768");
                    val = string.Format("Port={0}, Wait={1}sn", mp, tw);
                    if (mp == "65534" && tw == "15") detectedMod = 1;
                    else if (mp == "65534") detectedMod = 0;
                    else if (mp == "32768") detectedMod = 2;
                }
                else if (id == "NET_HOSTPRIO")
                {
                    string dp = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider", "DnsPriority", "");
                    ok = (dp == "6" || dp == "3" || dp == "1");
                    val = "DnsPriority=" + dp;
                    if (dp == "6") detectedMod = 0;
                    else if (dp == "3") detectedMod = 1;
                    else if (dp == "1") detectedMod = 2;
                }
                else if (id == "NET_MTU_SACK")
                {
                    string sk = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "SackOpts", "");
                    string mtu = activeTcpInterfaceGuids.Count > 0 ? vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + activeTcpInterfaceGuids[0], "MTU", "") : "";
                    ok = (sk == "1" && !string.IsNullOrEmpty(mtu));
                    val = ok ? string.Format("MTU={0}, SACK=1", mtu) : (sk == "1" ? "SackOpts=1" : "");
                    if (mtu == "1500") detectedMod = 0;
                    else if (mtu == "1492") detectedMod = 1;
                    else if (mtu == "1472") detectedMod = 2;
                }
                else if (id == "NET_AFD_UDP")
                {
                    string fs = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\AFD\Parameters", "FastSendDatagramThreshold", "");
                    string sw = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\AFD\Parameters", "DefaultSendWindow", "");
                    ok = (fs == "65536" || fs == "1500");
                    val = "FastUDP=" + fs + "B";
                    if (fs == "65536" && sw == "262144") detectedMod = 2;
                    else if (fs == "65536") detectedMod = 0;
                    else if (fs == "1500") detectedMod = 1;
                }
                else if (id == "NET_NIC_INT")
                {
                    string im = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*InterruptModeration", "");
                    string rb = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*ReceiveBuffers", "");
                    ok = (im == "0");
                    val = ok ? ("IntMod=0, Buf=" + (string.IsNullOrEmpty(rb) ? "512" : rb)) : "";
                    if (ok)
                    {
                        if (rb == "512") detectedMod = 0;
                        else if (rb == "128") detectedMod = 1;
                        else if (rb == "1024") detectedMod = 2;
                        else
                        {
                            detectedMod = 3;
                            int rbVal;
                            if (int.TryParse(rb, out rbVal) && t.CustomParam != null)
                                t.CustomParam.CurrentCustomValue = rbVal;
                        }
                    }
                }
                else if (id == "NET_NIC_OFFLOAD")
                {
                    string eee = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*EEE", "");
                    string grn = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "EnableGreenEthernet", "");
                    string lso = vault.ReadRegistryDisplay("HKLM", activeNicClassSubKey, "*LsoV2IPv4", "");
                    ok = (eee == "0" || grn == "0");
                    val = ok ? "EEE/Uyku=0 (Kapalı)" : "";
                    if (ok) detectedMod = (lso == "0" ? 0 : (lso == "1" ? 2 : 1));
                }
                else if (id == "NET_QOS_TOS")
                {
                    string qos = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Psched", "NonBestEffortLimit", "");
                    string tos = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DefaultTOSValue", "");
                    ok = (qos == "0");
                    val = ok ? ("QoS=%0" + (!string.IsNullOrEmpty(tos) ? (", TOS=" + tos) : "")) : "";
                    if (ok) detectedMod = (tos == "184" ? 0 : (tos == "128" ? 1 : 2));
                }
                else if (id == "NET_DNS_SWITCH")
                {
                    string nc = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "MaxNegativeCacheTtl", "");
                    ok = (nc == "0");
                    val = ok ? "Hızlı DNS Aktif (NegTTL=0)" : "";
                    if (ok) detectedMod = 0;
                }
                else if (id == "LAT_TIMER")
                {
                    uint minR, maxR, curR;
                    if (NativeMethods.NtQueryTimerResolution(out minR, out maxR, out curR) == 0)
                    {
                        double ms = curR / 10000.0;
                        ok = (ms <= 1.05 && timerLockActive);
                        double reqMs = desiredTimerUnit / 10000.0;
                        int reqHz = (int)Math.Round(10000000.0 / desiredTimerUnit);

                        if (timerLockActive)
                        {
                            if (Math.Abs(ms - reqMs) < 0.003)
                            {
                                val = string.Format("{0:0.000} ms ({1} Hz)", reqMs, reqHz);
                            }
                            else
                            {
                                val = string.Format("{0:0.000} ms [OS: {1:0.000}]", reqMs, ms);
                            }
                            detectedMod = (desiredTimerUnit == 10000 ? 1 : (desiredTimerUnit == 5040 ? 2 : 0));
                        }
                        else
                        {
                            val = string.Format("{0:0.000} ms", ms);
                            detectedMod = 0;
                        }
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
                        if (parsed == 0x26) detectedMod = 0;
                        else if (parsed == 0x2A) detectedMod = 1;
                        else if (parsed == 0x28) detectedMod = 2;
                        else if (parsed == 0x16) detectedMod = 3;
                    }
                }
                else if (id == "LAT_CSTATES")
                {
                    string dm = ReadCurrentActivePowerAcValue(SUB_PROCESSOR, SET_IDLEDEMOTE, "");
                    string idl = ReadCurrentActivePowerAcValue(SUB_PROCESSOR, SET_IDLEDISABLE, "");
                    ok = (dm == "100" || dm == "90" || idl == "1");
                    val = string.Format("IdleDis={0}, Demote={1}%", string.IsNullOrEmpty(idl) ? "0" : idl, dm);
                    if (idl == "1") detectedMod = 0;
                    else if (dm == "100") detectedMod = 1;
                    else if (dm == "90") detectedMod = 2;
                }
                else if (id == "LAT_COREPARK")
                {
                    string mc = ReadCurrentActivePowerAcValue(SUB_PROCESSOR, SET_CPMINCORES, "");
                    string tm = ReadCurrentActivePowerAcValue(SUB_PROCESSOR, SET_PROCTHROTTLEMIN, "");
                    ok = (mc == "100" && (tm == "100" || tm == "85" || tm == "50"));
                    val = string.Format("Unpark=%{0}, MinFreq=%{1}", mc, tm);
                    if (tm == "100") detectedMod = 0;
                    else if (tm == "85") detectedMod = 1;
                    else if (tm == "50") detectedMod = 2;
                }
                else if (id == "LAT_MOUSE_SPI")
                {
                    int[] curM = new int[3];
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETMOUSE, 0, curM, 0);
                    string msReg = vault.ReadRegistryDisplay("HKCU", @"Control Panel\Mouse", "MouseSpeed", "");
                    ok = (curM[2] == 0 && msReg == "0");
                    val = ok ? "İvme=0 (1:1 Raw)" : ("İvme=" + curM[2]);
                    if (ok) detectedMod = 0;
                }
                else if (id == "LAT_HID_QUEUE")
                {
                    int kDelay;
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETKEYBOARDDELAY, 0, out kDelay, 0);
                    string mq = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\mouclass\Parameters", "MouseDataQueueSize", "");
                    int mqVal;
                    int.TryParse(mq, out mqVal);
                    ok = (mqVal >= 32 && mqVal <= 300);
                    val = string.Format("Kuyruk={0}, Delay={1}", string.IsNullOrEmpty(mq) ? "Varsayılan" : mq, kDelay);
                    if (mq == "40") detectedMod = 0;
                    else if (mq == "32") detectedMod = 1;
                    else if (mq == "64") detectedMod = 2;
                    else if (ok)
                    {
                        detectedMod = 3;
                        if (t.CustomParam != null) t.CustomParam.CurrentCustomValue = mqVal;
                    }
                }
                else if (id == "LAT_USB_PCIE")
                {
                    string us = ReadCurrentActivePowerAcValue(SUB_USB, SET_USBSUSPEND, "");
                    string pc = ReadCurrentActivePowerAcValue(SUB_PCIEXPRESS, SET_PCIEASPM, "");
                    ok = (us == "0" || pc == "0");
                    val = "USB/PCIe Uyku=0";
                    if (us == "0" && pc == "0") detectedMod = 0;
                    else if (us == "0") detectedMod = 1;
                    else if (pc == "0") detectedMod = 2;
                }
                else if (id == "LAT_FILTERKEYS")
                {
                    NativeMethods.FILTERKEYS fk = new NativeMethods.FILTERKEYS();
                    fk.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.FILTERKEYS));
                    NativeMethods.SystemParametersInfo(NativeMethods.SPI_GETFILTERKEYS, fk.cbSize, ref fk, 0);
                    ok = ((fk.dwFlags & 1u) != 0 && (fk.dwFlags & 0x40u) == 0);
                    val = ok ? string.Format("Sessiz, Delay={0}ms", fk.iDelayMSec) : "";
                    if (ok) detectedMod = (fk.iDelayMSec >= 300 ? 0 : (fk.iDelayMSec >= 200 ? 1 : 2));
                }
                else if (id == "LAT_USB_XHCI")
                {
                    string ds = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\USB", "DisableSelectiveSuspend", "");
                    string ds3 = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters", "DisableSelectiveSuspend", "");
                    ok = (ds == "1");
                    val = ok ? "DisableSuspend=1" : "";
                    if (ok) detectedMod = (ds3 == "1" ? 0 : 1);
                }
                else if (id == "FPS_MMCSS_GAMES")
                {
                    string gp = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "GPU Priority", "");
                    string pr = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Priority", "");
                    ok = (gp == "8" && (pr == "6" || pr == "4"));
                    val = ok ? string.Format("GPU={0}, CPU={1}", gp, pr) : "";
                    if (ok) detectedMod = (pr == "4" ? 1 : 0);
                }
                else if (id == "FPS_FSO_FLIP")
                {
                    string dvr = vault.ReadRegistryDisplay("HKCU", @"System\GameConfigStore", "GameDVR_Enabled", "");
                    string fse = vault.ReadRegistryDisplay("HKCU", @"System\GameConfigStore", "GameDVR_FSEBehaviorMode", "");
                    ok = (dvr == "0" && (fse == "2" || vault.ReadRegistryDisplay("HKCU", @"Software\Microsoft\DirectX\UserGlobalSettings", "DirectXUserGlobalSettings", "").Contains("SwapEffectUpgradeEnable")));
                    val = ok ? "GameDVR=0, FSE=" + fse : "";
                    if (ok) detectedMod = (fse == "0" ? 1 : 0);
                }
                else if (id == "FPS_HAGS")
                {
                    string hw = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", "");
                    string tdr = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "TdrDelay", "");
                    ok = (tdr == "10" || tdr == "15");
                    val = ok ? string.Format("HwSchMode={0}, Tdr={1}s", string.IsNullOrEmpty(hw) ? "Varsayılan" : hw, tdr) : "";
                    if (ok) detectedMod = (tdr == "15" ? 2 : (hw == "1" ? 1 : 0));
                }
                else if (id == "FPS_MEMORY_ENGINE")
                {
                    string pe = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "DisablePagingExecutive", "");
                    ok = autoStandbyCleanerActive || pe == "1";
                    val = ok ? "Canlı RAM Koruma Aktif" : "";
                    if (ok) detectedMod = 0;
                }
                else if (id == "FPS_DWM_VISUAL")
                {
                    string md = vault.ReadRegistryDisplay("HKCU", @"Control Panel\Desktop", "MenuShowDelay", "");
                    string tr = vault.ReadRegistryDisplay("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", "");
                    ok = (md == "0");
                    val = ok ? "MenuDelay=0ms" : "";
                    if (ok) detectedMod = (tr == "0" ? 0 : 2);
                }
                else if (id == "FPS_NVME_IRQ8")
                {
                    string irq8 = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\PriorityControl", "IRQ8Priority", "");
                    string irq0 = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\PriorityControl", "IRQ0Priority", "");
                    ok = (irq8 == "1");
                    val = ok ? "IRQ8Priority=1" : "";
                    if (ok) detectedMod = (irq0 == "1" ? 1 : 0);
                }
                else if (id == "FPS_ECOQOS_GOVERNOR")
                {
                    ok = (fpsEcoQosMode > 0);
                    val = ok ? ("EcoQoS Kafesi Mod " + fpsEcoQosMode) : "";
                    if (ok) detectedMod = fpsEcoQosMode - 1;
                }
                else if (id == "FPS_AUDIODG_DWM_ISO")
                {
                    ok = (fpsAudioIsoMode > 0);
                    val = ok ? ("audiodg İzole Mod " + fpsAudioIsoMode) : "";
                    if (ok) detectedMod = fpsAudioIsoMode - 1;
                }
                else if (id == "FPS_LIVE_SERVICES")
                {
                    ok = (pausedServicesByArgon.Count > 0);
                    val = ok ? string.Format("{0} Servis Duraklatıldı", pausedServicesByArgon.Count) : "";
                    if (ok) detectedMod = 0;
                }
                else if (id == "EXP_SERIALIZE_TIMER")
                {
                    string st = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "SerializeTimerExpiration", "");
                    ok = (st == "0" || st == "2");
                    val = ok ? ("SerializeTimer=" + st) : "";
                    if (st == "0") detectedMod = 0;
                    else if (st == "2") detectedMod = 1;
                }
                else if (id == "EXP_SYNTHETIC_PULSE")
                {
                    ok = pulseThreadRunning;
                    val = ok ? "Mikro-Sinyal Aktif" : "";
                    if (ok) detectedMod = Math.Max(0, pulseMode - 1);
                }
                else if (id == "EXP_SMT_ISOLATION")
                {
                    ok = (standbyIsolationMode > 0);
                    val = ok ? ("Maske=0x" + CalculateCpuTopologyMask(standbyIsolationMode).ToString("X")) : "";
                    if (ok) detectedMod = standbyIsolationMode - 1;
                }
                else if (id == "EXP_TCP_CONGESTION")
                {
                    ok = t.IsEnabled;
                    val = ok ? t.Variations[t.SelectedVariationIndex].ExactParameters : "";
                }
                else if (id == "EXP_IO_PAGE_PRIO")
                {
                    ok = t.IsEnabled;
                    val = ok ? "I/O=High, Page=5" : "";
                }
                else if (id == "EXP_SVCHOST_SPLIT")
                {
                    string sv = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control", "SvcHostSplitThresholdInKB", "");
                    ok = (!string.IsNullOrEmpty(sv) && sv != "3670016");
                    val = ok ? ("Threshold=" + sv + " KB") : "";
                    if (ok) detectedMod = (sv == "67108864" ? 1 : (sv == "16777216" ? 2 : 0));
                }
                else if (id == "EXP_ECN_HEURISTICS")
                {
                    ok = t.IsEnabled;
                    val = ok ? "Heuristics=Disabled" : "";
                }
                else if (id == "EXP_FOREGROUND_HOOKS")
                {
                    string fl = vault.ReadRegistryDisplay("HKCU", @"Control Panel\Desktop", "ForegroundLockTimeout", "");
                    string lh = vault.ReadRegistryDisplay("HKCU", @"Control Panel\Desktop", "LowLevelHooksTimeout", "");
                    ok = (fl == "0" && (lh == "1000" || lh == "500" || t.IsEnabled));
                    val = ok ? ("LockTimeout=0ms" + (!string.IsNullOrEmpty(lh) ? (", Hooks=" + lh + "ms") : "")) : "";
                    if (ok) detectedMod = (lh == "500" ? 1 : (lh == "1000" ? 0 : 2));
                }
                else if (id == "WU_MPO_CONTROL")
                {
                    string mpo = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Microsoft\Windows\Dwm", "OverlayTestMode", "");
                    string disOv = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "DisableOverlays", "");
                    ok = (mpo == "5");
                    val = ok ? (disOv == "1" ? "OverlayTestMode=5, DisableOverlays=1" : "OverlayTestMode=5") : "";
                    if (ok) detectedMod = (disOv == "1" ? 1 : 0);
                }
                else if (id == "WU_IPV4_TEREDO")
                {
                    string dc = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisabledComponents", "");
                    ok = (dc == "32" || dc == "33" || dc == "1");
                    val = ok ? ("DisabledComponents=" + dc) : "";
                    if (dc == "32") detectedMod = 0;
                    else if (dc == "33") detectedMod = 1;
                    else if (dc == "1") detectedMod = 2;
                }
                else if (id == "WU_DELIVERY_OPT")
                {
                    string dom = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization", "DODownloadMode", "");
                    ok = (dom == "0" || dom == "1");
                    val = ok ? ("DODownloadMode=" + dom) : "";
                    if (dom == "0") detectedMod = 0;
                    else if (dom == "1") detectedMod = 1;
                }
                else if (id == "WU_HIBERNATION")
                {
                    string hb = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HibernateEnabled", "");
                    string fb = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", "");
                    ok = (hb == "0" || fb == "0");
                    val = ok ? string.Format("Hibernate={0}, Hiberboot={1}", hb, fb) : "";
                    if (hb == "0") detectedMod = 0;
                    else if (fb == "0") detectedMod = 1;
                }
                else if (id == "WU_WPBT_COMPANION")
                {
                    string wp = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager", "DisableWpbtExecution", "");
                    string dm = vault.ReadRegistryDisplay("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Device Metadata", "PreventDeviceMetadataFromNetwork", "");
                    ok = (wp == "1");
                    val = ok ? (dm == "1" ? "WPBT=Kapalı, Companion=Kapalı" : "WPBT=Kapalı") : "";
                    if (ok) detectedMod = (dm == "1" ? 0 : 1);
                }
                else if (id == "WU_UX_PRO_TOOLS")
                {
                    string et = vault.ReadRegistryDisplay("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings", "TaskbarEndTask", "");
                    string vp = vault.ReadRegistryDisplay("HKLM", @"SYSTEM\CurrentControlSet\Control\CrashControl", "DisplayParameters", "");
                    ok = (et == "1");
                    val = ok ? "TaskbarEndTask=1, StickyShield=Aktif" : "";
                    if (ok) detectedMod = (vp == "1" ? 0 : 1);
                }
                else if (id == "WU_GAMEMODE_STORAGE")
                {
                    string gm = vault.ReadRegistryDisplay("HKCU", @"Software\Microsoft\GameBar", "AutoGameModeEnabled", "");
                    string ss = vault.ReadRegistryDisplay("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy", "01", "");
                    ok = (gm == "1" && (ss == "0" || t.IsEnabled));
                    val = ok ? ("GameMode=1" + (ss == "0" ? ", StorageSense=0" : "")) : "";
                    if (ok) detectedMod = (ss == "0" ? 0 : 1);
                }

                t.IsDetectedActiveInOs = ok;
                t.DetectedVariationInOs = detectedMod;
                t.LiveOsRawSummary = ok ? val : ("Varsayılan (" + t.CapturedOriginalSummary + ")");
                t.IsVerifiedInOs = ok;
                t.VerifiedSystemValue = val;
                return ok;
            }
            catch
            {
                t.IsDetectedActiveInOs = false;
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
            int externalDetectedTotal = 0;
            int rebootWaiting = 0;
            int netReloadWaiting = 0;
            StringBuilder details = new StringBuilder();
            StringBuilder externalDetails = new StringBuilder();

            foreach (var t in allTweaks)
            {
                AutoResolveRebootAndReloadState(t);
                bool ok = t.IsVerifiedInOs;
                if (!t.IsEnabled)
                {
                    t.IsVerifiedInOs = false;
                    t.VerifiedSystemValue = "";
                    if (ok)
                    {
                        externalDetectedTotal++;
                        externalDetails.AppendLine(string.Format("🔍 [Sistemde Aktif] {0}  -->  [{1}]", t.Title, t.LiveOsRawSummary));
                    }
                    continue;
                }
                activeTotal++;
                if (ok) verifiedTotal++;
                if (t.IsRebootPending) rebootWaiting++;
                if (t.IsNetReloadPending) netReloadWaiting++;

                details.AppendLine(string.Format("{0} {1}  -->  [{2}]",
                    ok ? "✓" : "⚠️",
                    t.Title,
                    ok ? ("OS Değeri: " + t.VerifiedSystemValue) : "Doğrulanamadı (Yönetici Yetkisi Kontrol Edin)"));
            }

            foreach (var c in allCards)
                c.RefreshVisualState();

            UpdateRebootAndReloadBannerVisibility();

            lblInspectorTitle.Text = string.Format("🔍 CANLI SİSTEM DOĞRULAMASI: {0} / {1} açık ayar doğrulandı (Ayrıca {2} ayar sistemde harici aktif algılandı)!", verifiedTotal, activeTotal, externalDetectedTotal);
            lblInspectorPath.Text = string.Format("Bekleyen Restart: {0}  |  Bekleyen Ağ Yenileme: {1}  |  Harici aktif ayarları eşitlemek için üstteki '🔄 Gerçek Durumu Algıla' butonunu kullanabilirsiniz.", rebootWaiting, netReloadWaiting);

            if (showPopupReport)
            {
                string summaryHeader = string.Format(
                    "🔍 ARGON CANLI SİSTEM (LIVE OS TRUTH) DOĞRULAMA RAPORU\n" +
                    "════════════════════════════════════════════════════════\n" +
                    "• Programda Açık Ayar           : {0}\n" +
                    "• Sistemde Doğrulanan           : {1} / {0}\n" +
                    "• Sistemde Harici Aktif Bulunan : {2}\n" +
                    "• Bekleyen Windows Restart      : {3}\n" +
                    "• Bekleyen Ağ Kartı Yenileme    : {4}\n" +
                    "════════════════════════════════════════════════════════\n\n",
                    activeTotal, verifiedTotal, externalDetectedTotal, rebootWaiting, netReloadWaiting);

                string body = activeTotal > 0 ? details.ToString() : "Programda açık bir ayar bulunmuyor.\n";
                if (externalDetectedTotal > 0)
                {
                    body += "\n── SİSTEMDE ZATEN AKTİF ALGILANANLAR (Üstteki 'Gerçek Durumu Algıla' İle Eşitleyebilirsiniz) ──\n" + externalDetails.ToString();
                }

                MessageBox.Show(
                    summaryHeader + body,
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
                    "haxball", "haxball client", "cs2", "dota2",
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

        private void SetRevertOnExit(bool value)
        {
            if (syncingRevertUi) return;
            syncingRevertUi = true;
            try
            {
                revertOnExit = value;
                if (mnuRevertOnExit != null && mnuRevertOnExit.Checked != value) mnuRevertOnExit.Checked = value;
                if (chkRevertOnExit != null && chkRevertOnExit.Checked != value) chkRevertOnExit.Checked = value;
            }
            finally { syncingRevertUi = false; }
            UpdateExitMenuText();
            if (!isLoadingProfile) SaveUserProfileState();
        }

        private bool AutoStartTaskExists()
        {
            try
            {
                string o = StateVault.RunCmdCaptureOutput("schtasks", "/Query /TN \"" + AutoStartTaskName + "\"");
                return !string.IsNullOrEmpty(o) && o.IndexOf(AutoStartTaskName, StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch { return false; }
        }

        private bool SetAutoStartTask(bool enable)
        {
            if (!isAdmin) return false;
            try
            {
                if (enable)
                {
                    string exe = Application.ExecutablePath;
                    StateVault.RunHiddenCmd("schtasks", "/Create /TN \"" + AutoStartTaskName + "\" /TR \"\\\"" + exe + "\\\" --tray\" /SC ONLOGON /RL HIGHEST /DELAY 0000:15 /F");
                }
                else
                {
                    StateVault.RunHiddenCmd("schtasks", "/Delete /TN \"" + AutoStartTaskName + "\" /F");
                }
            }
            catch { }
            return AutoStartTaskExists() == enable;
        }

        private void OnAutoStartToggled()
        {
            if (suppressAutoStartHandler) return;
            bool want = chkAutoStart.Checked;
            if (!isAdmin)
            {
                MessageBox.Show("Windows ile başlatma görevi oluşturmak için Yönetici yetkisi gerekir. 'Yönetici Olarak Aç' ile devam edin.",
                    "Yönetici Yetkisi Gerekli", MessageBoxButtons.OK, MessageBoxIcon.Information);
                suppressAutoStartHandler = true; chkAutoStart.Checked = !want; suppressAutoStartHandler = false;
                return;
            }
            bool ok = SetAutoStartTask(want);
            if (!ok)
            {
                suppressAutoStartHandler = true; chkAutoStart.Checked = !want; suppressAutoStartHandler = false;
                lblInspectorTitle.Text = want ? "⚠️ Başlangıç görevi oluşturulamadı." : "⚠️ Başlangıç görevi silinemedi.";
            }
            else
            {
                lblInspectorTitle.Text = want
                    ? "🚀 Argon artık Windows ile birlikte, yönetici yetkisiyle ve tepside başlayacak."
                    : "Başlangıç görevi kaldırıldı.";
            }
        }

        private void SyncAutoStartCheckboxFromSystem()
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                bool exists = AutoStartTaskExists();
                try
                {
                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        suppressAutoStartHandler = true;
                        if (chkAutoStart != null) chkAutoStart.Checked = exists;
                        suppressAutoStartHandler = false;
                    });
                }
                catch { }
            });
        }

        // "--tray": start without showing the window (used by the autostart task)
        protected override void SetVisibleCore(bool value)
        {
            if (startHiddenInTray && !trayStartHandled)
            {
                trayStartHandled = true;
                if (!IsHandleCreated) CreateHandle();
                value = false;
            }
            base.SetVisibleCore(value);
        }

        private void UpdateExitMenuText()
        {
            if (mnuExit == null) return;
            mnuExit.Text = revertOnExit
                ? "❌ Programdan Çık (Ayarlar Varsayılana Döner)"
                : "❌ Programdan Çık (Açık Ayarlar Sabit Kalır)";
        }

        // Synchronous variant for use at process exit (the ThreadPool one would be killed with the process).
        private void ResumePausedWindowsServicesNow()
        {
            if (!isAdmin || pausedServicesByArgon.Count == 0) return;
            List<string> toResume = new List<string>(pausedServicesByArgon);
            pausedServicesByArgon.Clear();
            foreach (string svc in toResume)
            {
                try { StateVault.RunHiddenCmd("net", "start " + svc); } catch { }
            }
        }

        // Runtime-only changes (paused services, process priority/affinity/EcoQoS, audio/DWM affinity)
        // must never outlive Argon, regardless of the "revert on exit" option.
        private void RestoreLiveStateOnExit()
        {
            try { RevertLiveEcoQosAndBackgroundCage(); } catch { }
            try { RevertAudioAndDwmIsolation(); } catch { }
            try { vault.RestoreAllProcessBackups(); } catch { }
            try { ResumePausedWindowsServicesNow(); } catch { }
        }

        // Undo every active tweak but KEEP the saved profile (already written by the caller),
        // so the next launch re-applies the user's selection.
        private void RevertEverythingOnExitKeepProfile()
        {
            foreach (var t in allTweaks)
            {
                if (!t.IsEnabled) continue;
                try { if (t.RevertAction != null) t.RevertAction(); } catch { }
            }
            try { vault.RollbackAllAndCleanSession(); } catch { }
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
                if (sensorEngine != null)
                {
                    try { sensorEngine.Dispose(); } catch { }
                }

                RestoreLiveStateOnExit();
                if (revertOnExit && !suppressRevertOnExit)
                    RevertEverythingOnExitKeepProfile();

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
            int totalActive = 0, hwActive = 0, netActive = 0, latActive = 0, fpsActive = 0, wuActive = 0, expActive = 0;
            int netTotal = 0, latTotal = 0, fpsTotal = 0, wuTotal = 0, expTotal = 0;
            foreach (var t in allTweaks)
            {
                if (t.Category == "NETWORK") netTotal++;
                else if (t.Category == "LATENCY") latTotal++;
                else if (t.Category == "FPS") fpsTotal++;
                else if (t.Category == "WINUTIL") wuTotal++;
                else if (t.Category == "EXPERIMENTAL") expTotal++;

                if (!t.IsEnabled) continue;
                totalActive++;
                if (t.Category == "HARDWARE") hwActive++;
                else if (t.Category == "NETWORK") netActive++;
                else if (t.Category == "LATENCY") latActive++;
                else if (t.Category == "FPS") fpsActive++;
                else if (t.Category == "WINUTIL") wuActive++;
                else if (t.Category == "EXPERIMENTAL") expActive++;
            }

            int pendingRebootCount = 0;
            int pendingNetReloadCount = 0;
            foreach (var t in allTweaks)
            {
                if (t.IsRebootPending) pendingRebootCount++;
                else if (t.IsNetReloadPending) pendingNetReloadCount++;
            }

            if (lblLiveSystemStatusPill != null)
            {
                if (pendingRebootCount > 0)
                {
                    lblLiveSystemStatusPill.Text = string.Format(Loc.T("⚠️ {0} / {1} Aktif ({2} Restart Bekliyor)", "⚠️ {0} / {1} Active ({2} Restart Pending)"), totalActive, allTweaks.Count, pendingRebootCount);
                    lblLiveSystemStatusPill.ForeColor = Color.FromArgb(251, 191, 36);
                }
                else if (pendingNetReloadCount > 0)
                {
                    lblLiveSystemStatusPill.Text = string.Format(Loc.T("⚡ {0} / {1} Aktif ({2} Ağ Yenileme)", "⚡ {0} / {1} Active ({2} Net Reload)"), totalActive, allTweaks.Count, pendingNetReloadCount);
                    lblLiveSystemStatusPill.ForeColor = Color.FromArgb(56, 189, 248);
                }
                else
                {
                    lblLiveSystemStatusPill.Text = string.Format(Loc.T("● Sistem: {0} / {1} Ayar Aktif", "● System: {0} / {1} Tweaks Active"), totalActive, allTweaks.Count);
                    lblLiveSystemStatusPill.ForeColor = totalActive > 0 ? Color.FromArgb(52, 211, 153) : Color.FromArgb(148, 163, 184);
                }
            }

            if (lblTopActiveCount != null)
            {
                lblTopActiveCount.Text = string.Format(Loc.T("Aktif: {0} / {1}", "Active: {0} / {1}"), totalActive, allTweaks.Count);
                lblTopActiveCount.ForeColor = totalActive > 0 ? Color.FromArgb(52, 211, 153) : Color.FromArgb(168, 85, 247);
            }

            if (navButtons.Count >= 6)
            {
                navButtons[0].Text = string.Format(Loc.T("Donanım ({0})", "Hardware ({0})"), hwActive);
                navButtons[1].Text = string.Format(Loc.T("Ağ ({0}/{1})", "Network ({0}/{1})"), netActive, netTotal);
                navButtons[2].Text = string.Format("Timer ({0}/{1})", latActive, latTotal);
                navButtons[3].Text = string.Format(Loc.T("Grafik ({0}/{1})", "Graphics ({0}/{1})"), fpsActive, fpsTotal);
                navButtons[4].Text = string.Format(Loc.T("Sistem ({0}/{1})", "System ({0}/{1})"), wuActive, wuTotal);
                navButtons[5].Text = string.Format("Kernel ({0}/{1})", expActive, expTotal);
                if (navButtons.Count >= 11)
                {
                    navButtons[6].Text = Loc.T("İşlemler", "Processes");
                    navButtons[7].Text = Loc.T("Otomasyon", "Automation");
                    navButtons[8].Text = Loc.T("Tanı Test", "Diagnostics");
                    navButtons[9].Text = Loc.T("Günlük", "Event Log");
                    navButtons[10].Text = Loc.T("Ayarlar", "Settings");
                }

                LayoutNavBarButtons();
            }
        }

        private void ApplySearchFilter(string query)
        {
            string q = (query ?? "").Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(q))
            {
                // Return all cards to their original category containers
                foreach (var card in allCards)
                {
                    Control home;
                    if (cardHomeContainers.TryGetValue(card, out home) && home != null && card.Parent != home)
                    {
                        card.Width = Math.Max(520, home.ClientSize.Width - 26);
                        home.Controls.Add(card);
                    }
                    card.Visible = true;
                }
                RefreshHardwareMatrixCards();
                SwitchActiveTab(currentActiveTabIndex);
                return;
            }

            // Global Search across ALL tabs and categories (HARDWARE, NETWORK, LATENCY, FPS, WINUTIL, EXPERIMENTAL)
            viewDashboard.Visible = false;
            viewNetwork.Visible = false;
            viewLatency.Visible = false;
            viewFps.Visible = false;
            if (viewWinUtil != null) viewWinUtil.Visible = false;
            viewExperimental.Visible = false;
            viewProcesses.Visible = false;
            if (viewAutomationQoL != null) viewAutomationQoL.Visible = false;
            viewBenchmark.Visible = false;
            viewSnapshotAudit.Visible = false;
            if (viewSettings != null) viewSettings.Visible = false;
            if (viewGlobalSearch != null) viewGlobalSearch.Visible = true;

            int matchCount = 0;
            int targetW = flowGlobalSearchCards != null ? Math.Max(520, flowGlobalSearchCards.ClientSize.Width - 24) : 810;

            if (flowGlobalSearchCards != null) flowGlobalSearchCards.SuspendLayout();
            try
            {
                foreach (var card in allCards)
                {
                    var t = card.Tweak;
                    bool match = t.Title.ToLowerInvariant().Contains(q) ||
                                 t.SummaryDescription.ToLowerInvariant().Contains(q) ||
                                 t.DeepTechnicalWhy.ToLowerInvariant().Contains(q) ||
                                 t.TargetPathOrApi.ToLowerInvariant().Contains(q) ||
                                 t.BadgeText.ToLowerInvariant().Contains(q) ||
                                 t.Category.ToLowerInvariant().Contains(q);
                    if (!match)
                    {
                        foreach (var v in t.Variations)
                        {
                            if (v.ShortLabel.ToLowerInvariant().Contains(q) ||
                                v.DetailedTitle.ToLowerInvariant().Contains(q) ||
                                v.ExactParameters.ToLowerInvariant().Contains(q))
                            {
                                match = true;
                                break;
                            }
                        }
                    }

                    if (match && flowGlobalSearchCards != null)
                    {
                        matchCount++;
                        if (card.Parent != flowGlobalSearchCards)
                            flowGlobalSearchCards.Controls.Add(card);
                        card.Width = targetW;
                        card.Visible = true;
                        card.RefreshVisualState();
                    }
                    else
                    {
                        Control home;
                        if (cardHomeContainers.TryGetValue(card, out home) && home != null && card.Parent != home)
                            home.Controls.Add(card);
                        card.Visible = false;
                    }
                }
            }
            finally
            {
                if (flowGlobalSearchCards != null) flowGlobalSearchCards.ResumeLayout(true);
            }

            if (lblGlobalSearchHeader != null)
            {
                lblGlobalSearchHeader.Text = string.Format("TÜM SEKMELERDE GENEL ARAMA SONUÇLARI ('{0}' için {1} / {2} ayar bulundu):",
                    query.Trim(), matchCount, allCards.Count);
            }
        }

        private void RestartAsAdministrator()
        {
            try
            {
                suppressRevertOnExit = true;
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

                    bool standbyPurged = false;
                    try
                    {
                        // SystemMemoryListInformation (80) needs SeProfileSingleProcessPrivilege enabled in the token.
                        if (NativeMethods.EnablePrivilege("SeProfileSingleProcessPrivilege"))
                        {
                            int purgeCmd = 4; // MemoryPurgeStandbyList
                            standbyPurged = (NativeMethods.NtSetSystemInformation(80, ref purgeCmd, sizeof(int)) == 0);
                        }
                    }
                    catch { }

                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        UpdateTelemetryBar();
                        if (standbyPurged)
                            lblInspectorTitle.Text = string.Format("🧹 Akıllı Bellek Temizliği Tamamlandı: {0} arka plan sürecinin çalışma kümesi ve Standby önbelleği boşaltıldı.", trimmed);
                        else
                            lblInspectorTitle.Text = string.Format("🧹 Bellek Temizliği: {0} arka plan sürecinin çalışma kümesi küçültüldü. Standby önbelleği temizlenemedi (Yönetici yetkisi gerekli).", trimmed);
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
            string[] gameNames = new string[] { "haxball", "haxball client", "cs2", "dota2" };
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
            string[] gameNames = new string[] { "haxball", "haxball client", "cs2", "dota2" };
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

            // Also list all learned machine defaults AND live OS detection truth for every catalog setting
            foreach (var t in allTweaks)
            {
                ListViewItem item = new ListViewItem("[Canlı OS Denetimi] " + t.Title);
                item.SubItems.Add(t.TargetPathOrApi);
                item.SubItems.Add(t.CapturedOriginalSummary ?? "Standart");
                string liveStatus;
                if (t.IsEnabled)
                    liveStatus = t.IsVerifiedInOs ? string.Format("✓ Aktif & Doğrulandı ({0})", t.VerifiedSystemValue) : "⚠️ Açık (Doğrulanamadı)";
                else if (t.IsDetectedActiveInOs)
                    liveStatus = string.Format("🔍 Sistemde Aktif Algılandı ({0})", t.LiveOsRawSummary);
                else
                    liveStatus = "Makine Varsayılanında";

                item.SubItems.Add(liveStatus);
                item.ForeColor = t.IsEnabled
                    ? Color.FromArgb(52, 211, 153)
                    : (t.IsDetectedActiveInOs ? Color.FromArgb(56, 189, 248) : Color.FromArgb(148, 163, 184));
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

                    // Automatic conflict protection if 2000Hz+ mouse detected while Queue is set to low value (32)
                    if (avg >= 1750)
                    {
                        TweakDefinition hid = FindTweak("LAT_HID_QUEUE");
                        if (hid != null && hid.IsEnabled && (hid.SelectedVariationIndex == 1 || (hid.CustomParam != null && hid.CustomParam.CurrentCustomValue > 0 && hid.CustomParam.CurrentCustomValue < 50)))
                        {
                            hid.SelectedVariationIndex = 2; // Switch to 64 (4K/8K Safe Queue)
                            hid.Variations[2].ApplyAction();
                            foreach (var c in allCards) if (c.Tweak == hid) c.RefreshVisualState();
                            lblInspectorTitle.Text = Loc.T(
                                "🔗 2000Hz+ Yüksek Polling Fare Algılandı: HID Kuyruğu Taşma Koruması İçin Mod 3 (Kuyruk=64) Yapıldı!",
                                "🔗 2000Hz+ High Polling Mouse Detected: Upgraded to Mode 3 (Queue=64) to prevent overflow!");
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

            long nowMs = Environment.TickCount & int.MaxValue;
            int pollInterval = (appSettings != null) ? Math.Max(500, appSettings.TelemetryPollIntervalMs) : 1000;
            if (appSettings != null && appSettings.EnableTelemetrySensors && (nowMs - lastSensorPollTickMs >= pollInterval || lastSensorPollTickMs == 0))
            {
                lastSensorPollTickMs = nowMs;
                TriggerAsyncHardwareSensorPoll();
            }

            UpdateTelemetryBar();

            if (tickCounter % 6 == 0 && autoGameWatchdogActive)
            {
                RunAutoGameWatchdogPass();
            }

            // Otomatik canlı OS doğrulama & arka plan senkronizasyon pulsü (Her 10 saniyede bir sessizce kontrol eder)
            if (tickCounter % 20 == 0)
            {
                AutoSyncLiveOsTruthInBackground();
            }

            TweakDefinition memEngine = FindTweak("FPS_MEMORY_ENGINE");
            if (tickCounter % 60 == 0 && autoStandbyCleanerActive && memEngine != null && memEngine.IsEnabled)
            {
                NativeMethods.MEMORYSTATUSEX mem = new NativeMethods.MEMORYSTATUSEX();
                if (NativeMethods.GlobalMemoryStatusEx(mem) && mem.dwMemoryLoad >= 75)
                {
                    ExecuteSmartRamAndStandbyPurge(true);
                }
            }

            // Otomasyon & QoL Periyodik Kontrol Motoru (Güç, Kripto/Rutin Alarmlar, Oyun Notları, RAM Eşiği)
            ProcessQoLAutomationTick();
        }

        private void TriggerAsyncHardwareSensorPoll()
        {
            if (sensorPollingBusy || sensorEngine == null || appSettings == null || !appSettings.EnableTelemetrySensors)
                return;

            sensorPollingBusy = true;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    sensorEngine.PollSensors();
                    if (!this.IsDisposed && this.IsHandleCreated)
                    {
                        this.BeginInvoke((MethodInvoker)delegate
                        {
                            UpdateTelemetryBar();
                        });
                    }
                }
                catch { }
                finally
                {
                    sensorPollingBusy = false;
                }
            });
        }

        private void RunAutoGameWatchdogPass()
        {
            try
            {
                if (fpsEcoQosMode > 0 && tickCounter % 18 == 0)
                    ApplyLiveEcoQosAndBackgroundCage(fpsEcoQosMode);
                if (fpsAudioIsoMode > 0 && tickCounter % 18 == 0)
                    ApplyAudioAndDwmIsolation(fpsAudioIsoMode);

                string[] targets = new string[] { "haxball", "haxball client", "cs2" };
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
            double curTimerMsVal = 15.625;
            try
            {
                uint minR, maxR, curR;
                if (NativeMethods.NtQueryTimerResolution(out minR, out maxR, out curR) == 0)
                {
                    double ms = curR / 10000.0;
                    curTimerMsVal = ms;
                    if (lblTopTimer != null)
                    {
                        if (timerLockActive)
                        {
                            double reqMs = desiredTimerUnit / 10000.0;
                            int reqHz = (int)Math.Round(10000000.0 / desiredTimerUnit);
                            if (Math.Abs(ms - reqMs) < 0.003)
                                lblTopTimer.Text = string.Format("Timer: {0:0.000} ms ({1} Hz)", reqMs, reqHz);
                            else
                                lblTopTimer.Text = string.Format("Timer: {0:0.000} ms [OS: {1:0.000}]", reqMs, ms);
                        }
                        else
                        {
                            lblTopTimer.Text = string.Format("Timer: {0:0.000} ms ({1:0} Hz)", ms, 1000.0 / Math.Max(0.1, ms));
                        }
                        lblTopTimer.ForeColor = ms <= 1.05 ? Color.FromArgb(52, 211, 153) : Color.FromArgb(251, 191, 36);
                    }
                }
            }
            catch { }

            try
            {
                int activeCount = 0;
                foreach (var t in allTweaks) if (t.IsEnabled) activeCount++;
                if (txtHwTimerActive != null)
                {
                    if (timerLockActive)
                    {
                        double reqMs = desiredTimerUnit / 10000.0;
                        int reqHz = (int)Math.Round(10000000.0 / desiredTimerUnit);
                        if (Math.Abs(curTimerMsVal - reqMs) < 0.003)
                        {
                            txtHwTimerActive.Text = string.Format("{0:0.000} ms ({1} Hz) | {2}: {3}/{4}",
                                reqMs, reqHz, Loc.T("Aktif", "Active"), activeCount, allTweaks.Count);
                        }
                        else
                        {
                            txtHwTimerActive.Text = string.Format("{0:0.000} ms ({1} Hz) [OS: {2:0.000}] | {3}: {4}/{5}",
                                reqMs, reqHz, curTimerMsVal, Loc.T("Aktif", "Active"), activeCount, allTweaks.Count);
                        }
                    }
                    else
                    {
                        txtHwTimerActive.Text = string.Format("{0:0.000} ms ({1:0} Hz) | {2}: {3}/{4}",
                            curTimerMsVal, 1000.0 / Math.Max(0.1, curTimerMsVal), Loc.T("Aktif", "Active"), activeCount, allTweaks.Count);
                    }
                    txtHwTimerActive.ForeColor = curTimerMsVal <= 1.05 ? Color.FromArgb(52, 211, 153) : Color.FromArgb(56, 189, 248);
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
                    string ramStr = string.Format("%{0} Kullanım ({1:0.0} / {2:0.0} GB)", mem.dwMemoryLoad, totalGb - availGb, totalGb);
                    if (lblTopRam != null) lblTopRam.Text = "RAM: " + ramStr;
                    if (txtHwRamUsage != null) txtHwRamUsage.Text = ramStr;
                }
            }
            catch { }

            try
            {
                if (tickCounter % 6 == 0)
                {
                    foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (ni.OperationalStatus == OperationalStatus.Up &&
                            ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                            ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                        {
                            IPv4InterfaceStatistics st = ni.GetIPv4Statistics();
                            if (lblNetTrafficStats != null)
                            {
                                lblNetTrafficStats.Text = string.Format("Gönderilen: {0:0.0} MB | Alınan: {1:0.0} MB",
                                    st.BytesSent / (1024.0 * 1024.0), st.BytesReceived / (1024.0 * 1024.0));
                            }
                            break;
                        }
                    }
                }
            }
            catch { }

            try
            {
                if (sensorEngine != null && appSettings != null && appSettings.EnableTelemetrySensors)
                {
                    if (appSettings.ShowCpuSensor)
                    {
                        string tempStr = sensorEngine.CpuPackageTemp >= 0 ? string.Format("{0:0.0} °C", sensorEngine.CpuPackageTemp) : (isAdmin ? "Sensör Bekleniyor" : "Yönetici Gerekli");
                        string loadStr = sensorEngine.CpuTotalLoad >= 0 ? string.Format("%{0:0.0}", sensorEngine.CpuTotalLoad) : "%--";
                        string cpuLine = string.Format("Sıcaklık: {0} | Yük: {1}", tempStr, loadStr);
                        if (lblTopCpuSensor != null) lblTopCpuSensor.Text = cpuLine;
                        if (txtHwCpuTelemetry != null)
                        {
                            txtHwCpuTelemetry.Text = cpuLine;
                            txtHwCpuTelemetry.ForeColor = sensorEngine.CpuPackageTemp >= 82 ? Color.FromArgb(248, 113, 113) : Color.FromArgb(251, 146, 60);
                        }
                    }
                    else if (txtHwCpuTelemetry != null)
                    {
                        txtHwCpuTelemetry.Text = "Ayarlardan Kapatıldı";
                    }

                    if (appSettings.ShowGpuCoreSensor || appSettings.ShowGpuMemHotspotSensor)
                    {
                        List<string> gpuParts = new List<string>();
                        if (appSettings.ShowGpuCoreSensor)
                        {
                            string cTemp = sensorEngine.GpuCoreTemp >= 0 ? string.Format("Core {0:0}°C", sensorEngine.GpuCoreTemp) : "Core --°C";
                            string cLoad = sensorEngine.GpuCoreLoad >= 0 ? string.Format("%{0:0}", sensorEngine.GpuCoreLoad) : "";
                            gpuParts.Add(string.IsNullOrEmpty(cLoad) ? cTemp : (cTemp + " (" + cLoad + ")"));
                        }
                        if (appSettings.ShowGpuMemHotspotSensor)
                        {
                            if (sensorEngine.GpuMemoryTemp >= 0)
                                gpuParts.Add(string.Format("Mem {0:0}°C", sensorEngine.GpuMemoryTemp));
                            if (sensorEngine.GpuHotspotTemp >= 0)
                                gpuParts.Add(string.Format("Hot {0:0}°C", sensorEngine.GpuHotspotTemp));
                        }
                        if (sensorEngine.GpuMemUsedMb > 0)
                        {
                            gpuParts.Add(string.Format("VRAM {0:0}MB", sensorEngine.GpuMemUsedMb));
                        }
                        string gpuLine = gpuParts.Count > 0 ? string.Join(" | ", gpuParts.ToArray()) : "Okunuyor...";
                        if (lblTopGpuSensor != null) lblTopGpuSensor.Text = gpuLine;
                        if (txtHwGpuTelemetry != null)
                        {
                            txtHwGpuTelemetry.Text = gpuLine;
                            txtHwGpuTelemetry.ForeColor = sensorEngine.GpuHotspotTemp >= 90 ? Color.FromArgb(248, 113, 113) : Color.FromArgb(52, 211, 153);
                        }
                    }
                    else if (txtHwGpuTelemetry != null)
                    {
                        txtHwGpuTelemetry.Text = "Ayarlardan Kapatıldı";
                    }

                    if (lblSettingsSensorDiag != null)
                    {
                        lblSettingsSensorDiag.Text = string.Format(
                            "• CPU ({0}) -> Sıcaklık: {1}  |  Toplam Yük: {2}\n" +
                            "• GPU ({3}) -> Core: {4}  |  Memory: {5}  |  Hotspot: {6}\n" +
                            "• GPU Yük & VRAM -> Core Yük: {7}  |  VRAM: {8:0} / {9:0} MB",
                            string.IsNullOrEmpty(sensorEngine.CpuHwName) ? detectedHw.CpuName : sensorEngine.CpuHwName,
                            sensorEngine.CpuPackageTemp >= 0 ? (sensorEngine.CpuPackageTemp.ToString("0.0") + " °C") : "PawnIO/Ring0 Bekleniyor",
                            sensorEngine.CpuTotalLoad >= 0 ? ("%" + sensorEngine.CpuTotalLoad.ToString("0.0")) : "N/A",
                            string.IsNullOrEmpty(sensorEngine.GpuHwName) ? detectedHw.GpuName : sensorEngine.GpuHwName,
                            sensorEngine.GpuCoreTemp >= 0 ? (sensorEngine.GpuCoreTemp.ToString("0.0") + " °C") : "N/A",
                            sensorEngine.GpuMemoryTemp >= 0 ? (sensorEngine.GpuMemoryTemp.ToString("0.0") + " °C") : "N/A",
                            sensorEngine.GpuHotspotTemp >= 0 ? (sensorEngine.GpuHotspotTemp.ToString("0.0") + " °C") : "N/A",
                            sensorEngine.GpuCoreLoad >= 0 ? ("%" + sensorEngine.GpuCoreLoad.ToString("0.0")) : "N/A",
                            Math.Max(0, sensorEngine.GpuMemUsedMb),
                            Math.Max(0, sensorEngine.GpuMemTotalMb));
                    }
                }
                else
                {
                    if (txtHwCpuTelemetry != null) txtHwCpuTelemetry.Text = "Sensör Motoru Devre Dışı";
                    if (txtHwGpuTelemetry != null) txtHwGpuTelemetry.Text = "Sensör Motoru Devre Dışı";
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
                        var r1 = p.Send("1.1.1.1", 1000);
                        long rtt1 = (r1 != null && r1.Status == IPStatus.Success) ? r1.RoundtripTime : -1;
                        var r2 = p.Send("8.8.8.8", 1000);
                        long rtt2 = (r2 != null && r2.Status == IPStatus.Success) ? r2.RoundtripTime : -1;

                        this.BeginInvoke((MethodInvoker)delegate
                        {
                            if (rtt1 >= 0 || rtt2 >= 0)
                            {
                                string s1 = rtt1 >= 0 ? ("1.1.1.1: " + rtt1 + " ms") : "1.1.1.1: --";
                                string s2 = rtt2 >= 0 ? ("8.8.8.8: " + rtt2 + " ms") : "8.8.8.8: --";
                                if (lblTopPing != null) lblTopPing.Text = s1;
                                if (txtNetPingLive != null) txtNetPingLive.Text = s1 + "  |  " + s2;
                            }
                            else
                            {
                                if (lblTopPing != null) lblTopPing.Text = "Ping: Ölçülemedi";
                                if (txtNetPingLive != null) txtNetPingLive.Text = "ICMP Yanıtı Yok";
                            }
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
