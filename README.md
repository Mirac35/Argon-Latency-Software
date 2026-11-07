# ⚡ Argon Low Latency & TCP Optimizer Studio (v3.8)

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%20Windows%2011-0078D6?logo=windows)](https://microsoft.com)
[![Language](https://img.shields.io/badge/Language-C%23%205.0%20%2F%20.NET%204.0+-239120?logo=c-sharp)](https://docs.microsoft.com/dotnet/csharp/)
[![Zero-Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Win32%20%26%20WinForms)-success)](#compilation--building)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, progressive hardware-aware latency reduction suite and comprehensive TCP Optimizer built specifically for competitive gaming (CS2, Valorant, Apex Legends, Fortnite, League of Legends, and WebRTC/P2P physics titles like HaxBall).

Written in clean, standalone C# with **zero external dependencies** and native Win32/Kernel API interop (`ntdll.dll`, `powrprof.dll`, `user32.dll`, `kernel32.dll`, `dnsapi.dll`).

---

## 🌟 Key Architectural Pillars

### 1. 🤖 Progressive Hardware Matrix (CPU + GPU Aware)
Automatically detects system topology or allows manual selection of hardware architectures with 3 progressive intensity tiers (**Tier 1: Balanced**, **Tier 2: Competitive Esports**, **Tier 3: Tournament Extreme**):
* **Intel Core Processors:**
  * *12th / 13th / 14th Gen & Ultra (Hybrid Architecture):* Thread Director scheduling policies (`HeteroPolicy=4`, `ShortSchedPolicy=1`) to lock gaming threads onto high-clocked P-Cores while offloading background tasks to E-Cores.
  * *9th / 10th / 11th Gen (Classic Architecture):* Homogeneous multi-core tuning with autonomous SpeedShift EPP=0.
* **AMD Ryzen & X3D Processors:**
  * *Zen 2 / 3 / 4 / 5 (5600, 7500F, 9600X, etc.):* CPPC autonomous zero-energy latency (`EPP=0`, `Autonomous=1`, `%100 Boost`).
  * *X3D 3D V-Cache (5800X3D, 7800X3D, 9800X3D):* Cache-preferred die affinity (`HeteroPolicy=0`, CCD0 cache core prioritization) to prevent thread hopping across non-v-cache dies.
* **NVIDIA GeForce Graphics:**
  * PowerMizer dynamic P-state throttle unlock (`DisableDynamicPstate=1`, `PerfLevelSrc=0x2222`).
  * Graphics driver DPC multi-core interrupt distribution (`RmGpsPsEnablePerCpuCoreDpc=1`).
* **AMD Radeon Graphics:**
  * Ultra-Low Power State (ULPS) and Deep-Sleep disable (`EnableUlps=0`, `PP_SclkDeepSleepDisable=1`).
  * Driver de-lag queue and stutter mitigation (`KMD_DeLagEnabled=1`, `StutterMode=0`, `FlipQueueSize=1`).
* **Intel Arc Graphics:**
  * PCIe ASPM bus power throttling disabled + Hardware-Accelerated GPU Scheduling (HAGS) alignment.

---

### 2. 🌐 Comprehensive TCP Optimizer Pro (12 Modules)
Full-featured network suite implementing every advanced registry and NDIS parameter with automated conflict resolution:
* **Nagle’s Algorithm Elimination:** Dual-layer `TcpAckFrequency=1`, `TCPNoDelay=1`, and `TcpDelAckTicks=0` on all active network adapter GUIDs.
* **TCP Window Auto-Tuning & RFC 1323:** Anti-Bufferbloat queue constraints (`restricted`) and selective timestamp suppression.
* **Windows Network Throttling Index:** Removes the built-in 10-packet-per-millisecond rate limiter (`NetworkThrottlingIndex=0xFFFFFFFF`, `SystemResponsiveness=0`).
* **Initial RTO (3000ms → 300ms):** Reduces packet retransmission timeout from 3 seconds down to 300ms for instantaneous packet loss recovery.
* **Dynamic Ephemeral Port Pool:** Increases available socket pool to 65,534 ports and lowers `TcpTimedWaitDelay` to 15–30s (essential for P2P/WebRTC lobby hosting).
* **DNS & Host Resolution Priority:** Prioritizes DNS cache and host resolution above local NetBIOS broadcasting (4/5/6/7).
* **MTU & MSS Alignment:** Instant sub-interface MTU adjustment (1500 for Fiber/Cable, 1492 for VDSL/PPPoE, 1472 for VPN/Overseas).
* **Winsock AFD Fast-Path:** Sets `FastSendDatagramThreshold=65536` for zero-copy kernel datagram routing.
* **NIC Interrupt Moderation & Ring Buffers:** Disables NIC-level packet batching and adjusts Rx/Tx buffers (128–1024).
* **Green Ethernet / EEE & Flow Control:** Prevents PHY/NIC energy-saving sleep drops.
* **QoS Bandwidth & DSCP Tagging:** Disables `%20` Windows background reservation (`NonBestEffortLimit=0`) and tags game traffic with Expedited Forwarding (DSCP 46 / ToS 184).
* **Live DNS Switcher:** Instant zero-reboot switching between Cloudflare (1.1.1.1), Google (8.8.8.8), and Quad9 (9.9.9.9).

---

### 3. ⏱️ Kernel Latency, Timers & Input Pipeline
* **High-Precision System Timer:** Locks Windows kernel scheduler tick rate to **0.500 ms (2000 Hz)** via undocumented `NtSetTimerResolution` and `timeBeginPeriod(1)`.
* **Win32PrioritySeparation Quantum:** Short, variable 3:1 foreground boost (`0x26`), fixed latency (`0x2A`), or high minimum frame pacing (`0x28`).
* **Processor C-States & Core Parking:** Bypasses deep CPU sleep states (C3/C6) and sets minimum core unpark to 100%.
* **1:1 Raw Mouse Input:** Disables enhanced pointer precision curves (`SPI_SETMOUSE`, `MouseSpeed=0`).
* **HID DataQueueSize:** Reduces kernel mouse/keyboard input queue buffer (16/24) for immediate tactile response.
* **Silent FilterKeys Engine:** 0ms debounce key repeat (`FKF_FILTERKEYSON | FKF_AVAILABLE`) with keystroke click sound explicitly disabled (`FKF_CLICKON = 0`).
* **USB Controller & Hub Sleep Shield:** Disables xHCI selective suspend across all root hubs.

---

### 4. 🚀 Zero-Reboot Live Process & FPS Governors (New in v3.8)
* **Background EcoQoS Cage & Game Anti-Throttling:** Uses `SetProcessInformation` and `NtSetInformationProcess` to place noisy background apps (Discord, Chrome, Steam WebHelper) into Efficiency Mode (`PROCESS_POWER_THROTTLING_EXECUTION_SPEED`) while granting games High I/O and Page Priority 5.
* **Windows Audio Graph (`audiodg.exe`) Core 0 Isolation:** Automatically isolates audio processing threads away from CPU Core 0 to prevent micro-stutters during heavy combat audio spikes.
* **Live Service Suspender:** Temporarily suspends heavy background indexing (`WSearch`), telemetry (`DiagTrack`), and `SysMain` during gaming sessions and seamlessly restores them upon exit.
* **Smart Standby RAM & Working Set Cleaner:** Periodically purges cached standby memory only when available RAM falls below threshold, protecting the foreground game's working set.
* **Fullscreen Optimization (FSO) & DirectX Flip Model:** Enforces borderless independent flip presentation (`SwapEffectUpgradeEnable=1`, `VRROptimizeEnable=1`) and disables GameDVR background recording.

---

### 5. 🛡️ Transactional StateVault & Live OS Verification
* **Automatic Baseline Capture:** On first launch, discovers and persists your machine's original factory values (`original_baseline_backup.txt`).
* **Real-Time Live OS Verification:** Actively cross-checks applied tweaks against live registry keys, active power schemes, and kernel timer queries (`VerifySingleTweakInLiveOs`).
* **Boot-Aware Status Badges:** Automatically marks tweaks as `✓ Doğrulandı (Restart Aktif)` once the computer reboots, preventing stale reboot warnings.
* **One-Click Factory Revert:** Safely rolls back all modified keys, power schemes, SPI input parameters, and netsh states in a single transaction.

---

### 6. 📊 Diagnostic & Benchmark Suite
* **Kernel Sleep Drift Jitter Analyzer:** Tests 25-iteration `Thread.Sleep(1)` wake-up variance against timer resolution.
* **Multi-Server Ping & Jitter Benchmark:** Real-time packet round-trip time and jitter analysis across Cloudflare and Google DNS.
* **Interactive Mouse Polling (Hz) & Frame Time Delta:** Real-time polling rate measurement (1000Hz, 2000Hz, 4000Hz, 8000Hz) with automated queue overflow protection.
* **Interactive Process Governor:** Live task manager table with single-click core affinity, priority elevation, and EcoQoS controls.

---

## 📁 Repository Structure

```
Argon-Latency-Studio/
├── .gitignore               # Standard C# / Visual Studio exclusions
├── LICENSE                  # MIT License
├── README.md                # Documentation & Architecture Guide
├── app.manifest             # Windows 10/11 DPI-Awareness & compatibility manifest
├── ArgonLatencyStudio.csproj# MSBuild C# project file
├── ArgonLatencyStudio.sln   # Visual Studio solution file
├── build.bat                # Zero-dependency standalone build script (csc.exe)
└── src/
    └── ArgonLatencyStudio.cs # Complete, unified source code (~7,000 lines)
```

---

## 🔨 Compilation & Building

### Method 1: Instant Standalone Build (No IDE Needed)
Double-click `build.bat` or run from PowerShell:
```cmd
build.bat
```
*(Uses the native C# compiler included with Windows: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`)*

### Method 2: Visual Studio (2019 / 2022)
1. Open `ArgonLatencyStudio.sln`.
2. Select **Release | x64**.
3. Press `Ctrl + Shift + B` to build.

### Method 3: Command Line (csc.exe Direct)
```powershell
& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:winexe /platform:x64 /optimize+ /out:"Argon_UltraLowLatency_v3.8.exe" /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Management.dll "src\ArgonLatencyStudio.cs"
```

## ⚠️ Safety & System Protection
* **No Overclocking / Voltage Alterations:** All modifications are 100% within Windows API and driver specification limits.
* **Zero System Bloating:** No background services or scheduled tasks are installed. Closing the application leaves only the user-selected registry settings active.
* **Complete Reversibility:** Click **"Makine Varsayılanlarına Döndür"** at any time to restore factory defaults.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
