# ⚡ Argon Düşük Gecikme & TCP Optimizer Studio (v3.8)

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%20Windows%2011-0078D6?logo=windows)](https://microsoft.com)
[![Dil](https://img.shields.io/badge/Dil-C%23%205.0%20%2F%20.NET%204.0+-239120?logo=c-sharp)](https://docs.microsoft.com/dotnet/csharp/)
[![Sıfır-Bağımlılık](https://img.shields.io/badge/Ba%C4%9F%C4%B1ml%C4%B1l%C4%B1k-S%C4%B1f%C4%B1r%20(Saf%20Win32%20%26%20WinForms)-success)](#-derleme--kaynaktan-%C3%A7al%C4%B1%C5%9Ft%C4%B1rma)
[![Lisans: MIT](https://img.shields.io/badge/Lisans-MIT-yellow.svg)](LICENSE)

**Argon Latency Studio**, rekabetçi espor oyunları  ve WebRTC / eşler arası (P2P) fizik motoruna sahip oyunlar (HaxBall vb.) için özel olarak tasarlanmış, **kademeli donanım duyarlı** gecikme düşürme ve kapsamlı bir **TCP Optimizer** yazılımıdır.

Herhangi bir harici kütüphane veya paket olmadan (**sıfır bağımlılık**), doğrudan Windows Çekirdek ve Sistem API'leri (`ntdll.dll`, `powrprof.dll`, `user32.dll`, `kernel32.dll`, `dnsapi.dll`) ile saf C# dilinde geliştirilmiştir.
Tüm ayarları açayım, bilgisayarım uçsun her şey 5000 fps olsun diye hayal kurmayın. Programın önceliği, düşük gecikme ve en stabil sistem tepkimesini yakalamaktır. 

Doğru kullanım senaryosu: 

Programı açtın -> İşine yarayan ayarları seçtin(Bazı ayarlar restart/oturum kapatma gerektirir. Yaptıysan->) -> Oyuna girdin -> Oynadın ve bitti -> Programa döndün -> Makine Varsayılanlarına Döndür ile oturumu sonlandırdın.


---

## 🌟 Temel Mimari Sütunlar

### 1. 🤖 Akıllı Donanım Matrisi (İşlemci ve Ekran Kartı Duyarlı)
Sistem donanım mimarinizi otomatik tespit eder ya da manuel seçim imkanı tanır. 3 farklı agresiflik seviyesi (**Kademe 1: Dengeli**, **Kademe 2: Rekabetçi Espor**, **Kademe 3: Turnuva Ekstrem**) sunar:
* **Intel Core İşlemciler:**
  * *12., 13., 14. Nesil ve Core Ultra (Hibrit Mimari):* Thread Director zamanlama politikaları (`HeteroPolicy=4`, `ShortSchedPolicy=1`) ile oyun iş parçacıklarını yüksek frekanslı P-Çekirdeklere kilitler, arka plan görevlerini E-Çekirdeklere dağıtır.
  * *9., 10., 11. Nesil (Klasik Mimari):* Homojen çoklu çekirdek optimizasyonu ve otonom SpeedShift (EPP=0) tepki süresi.
* **AMD Ryzen & X3D İşlemciler:**
  * *Zen 2 / 3 / 4 / 5 (5600, 7500F, 9600X vb.):* CPPC otonom sıfır enerji tasarruf gecikmesi (`EPP=0`, `Autonomous=1`, `%100 Boost`).
  * *X3D 3D V-Cache (5800X3D, 7800X3D, 9800X3D):* Önbellek öncelikli kalıp yönlendirmesi (`HeteroPolicy=0`, CCD0 V-Cache çekirdek kilidi) ile önbelleksiz kalıplara iş parçacığı sıçramasını engeller.
* **NVIDIA GeForce Ekran Kartları:**
  * PowerMizer dinamik P-State frekans düşürme kilidi açma (`DisableDynamicPstate=1`, `PerfLevelSrc=0x2222`).
  * Grafik sürücüsü DPC çoklu çekirdek kesme dağıtımı (`RmGpsPsEnablePerCpuCoreDpc=1`).
* **AMD Radeon Ekran Kartları:**
  * Ultra-Düşük Güç Durumu (ULPS) ve Derin Uyku kalkanı (`EnableUlps=0`, `PP_SclkDeepSleepDisable=1`).
  * Sürücü De-Lag gecikme kuyruğu ve takılma önleyici (`KMD_DeLagEnabled=1`, `StutterMode=0`, `FlipQueueSize=1`).
* **Intel Arc Ekran Kartları:**
  * PCIe ASPM veri yolu güç tasarrufu kalkanı + Donanım Hızlandırmalı GPU Zamanlaması (HAGS) optimizasyonu.

---

### 2. 🌐 Kapsamlı TCP Optimizer Pro Paketi (12 Modül)
Kayıt defteri ve NDIS parametrelerini çakışma korumalı olarak yapılandıran tam teşekküllü ağ motoru:
* **Nagle Algoritması İptali:** Aktif ağ adaptörlerinin tamamında çift katmanlı `TcpAckFrequency=1`, `TCPNoDelay=1` ve `TcpDelAckTicks=0` ile paket bekletme gecikmesini sıfırlar.
* **TCP Window Auto-Tuning & RFC 1323:** Bufferbloat (ağ şişmesi) önleyici pencere kısıtlamaları (`restricted`) ve seçici zaman damgası yönetimi.
* **Windows Ağ Kısıtlama İndeksi Kaldırma:** Windows'un dahili saniyede 10 paketlik ağ sınırlayıcısını tamamen devre dışı bırakır (`NetworkThrottlingIndex=0xFFFFFFFF`, `SystemResponsiveness=0`).
* **İlk RTO Süresi (3000ms → 300ms):** Paket kaybı durumunda yeniden iletim zaman aşımı süresini 3 saniyeden 300 milisaniyeye indirerek anlık paket toparlanması sağlar.
* **Dinamik Geçici Port Havuzu:** Kullanılabilir soket havuzunu 65.534 porta genişletir ve `TcpTimedWaitDelay` süresini 15–30 saniyeye düşürür (P2P/WebRTC oda kurucuları için kritik).
* **DNS ve İsim Çözümleme Önceliği:** DNS önbelleği ve yerel isim çözümleme önceliğini NetBIOS yayınlarının üzerine çıkarır (4/5/6/7).
* **MTU & MSS Doğrudan Hizalama:** Alt arabirim MTU değerini tek tıkla optimize eder (Fiber/Kablo: 1500, VDSL/PPPoE: 1492, VPN/Yurtdışı: 1472).
* **Winsock AFD Hızlı-Yol:** `FastSendDatagramThreshold=65536` ile sıfır kopyalı çekirdek veri paketi yönlendirmesi sağlar.
* **Ağ Kartı Kesme Uyumlulaştırma (Interrupt Moderation) & Halka Tamponları:** Ağ kartı seviyesinde paket paketleme gecikmesini kapatır ve RX/TX tamponlarını (128–1024) optimize eder.
* **Yeşil Ethernet / EEE & Akış Denetimi (Flow Control):** Ağ yongasının enerji tasarrufu uykusuna dalarak paket düşürmesini engeller.
* **QoS Bant Genişliği & DSCP Etiketleme:** Windows'un arka planda ayırdığı `%20` rezervasyonu kaldırır (`NonBestEffortLimit=0`) ve oyun trafiğini Hızlandırılmış İletim (DSCP 46 / CS6) ile etiketler.
* **Canlı DNS Değiştirici:** Cloudflare (1.1.1.1), Google (8.8.8.8) ve Quad9 (9.9.9.9) arasında yeniden başlatma gerektirmeyen anlık geçiş sağlar.

---

### 3. ⏱️ Çekirdek Gecikmesi, Zamanlayıcılar & Girdi Boru Hattı
* **Yüksek Hassasiyetli Sistem Zamanlayıcısı:** Windows çekirdek zamanlayıcı frekansını `NtSetTimerResolution` ve `timeBeginPeriod` üzerinden **0.500 ms (2000 Hz)** değerine sabitler.
* **Win32PrioritySeparation Quantum:** 3:1 ön plan odaklı işlemci quantum değeri (`0x26`), sabit gecikme (`0x2A`) veya yüksek minimum kare kararlılığı (`0x28`).
* **İşlemci C-Durumları & Çekirdek Parkı:** C3/C6 gibi derin uyku durumlarını atlar ve minimum çekirdek parkını %100 uyanık tutacak şekilde ayarlar.
* **1:1 Ham Fare Girişi (Raw Input):** Windows gelişmiş işaretçi hassasiyeti ve ivme eğrilerini iptal eder (`SPI_SETMOUSE`, `MouseSpeed=0`).
* **HID DataQueueSize:** Fare ve klavye donanım giriş tampon kuyruğunu (16/24) düşürerek anlık tepki sağlar.
* **Sessiz FilterKeys Motoru:** Tuş vuruş ses efekti tamamen kapatılmış (`FKF_CLICKON = 0`), 0ms debounce ile anlık tuş tekrar motoru.
* **USB Derin Uyku Kalkanı:** xHCI ana denetleyicilerinde ve kök hub'larda seçici askıya almayı engeller.

---

### 4. 🚀 Sıfır Yeniden Başlatma: Canlı İşlem Yöneticisi & FPS Valisi (v3.8)
* **Arka Plan EcoQoS Kafesi & Oyun Hızlandırma:** `SetProcessInformation` ve `NtSetInformationProcess` kullanarak Discord, Chrome ve Steam WebHelper gibi arka plan uygulamalarını Verimlilik Moduna (`PROCESS_POWER_THROTTLING_EXECUTION_SPEED`) alır; oyuna ise Yüksek G/Ç ve Sayfa Önceliği 5 atar.
* **Windows Ses Motoru (`audiodg.exe`) Çekirdek 0 İzolasyonu:** Ses motorunu CPU Çekirdek 0'dan izole ederek ağır çatışma sesleri sırasında oluşan mikro takılmaları önler.
* **Canlı Servis Askıya Alma:** Ağır Windows Arama (`WSearch`), Telemetri (`DiagTrack`) ve `SysMain` servislerini oyun esnasında askıya alır, çıkışta geri açar.
* **Akıllı Boş RAM & Çalışma Kümesi Temizliği:** Yalnızca boş RAM kritik seviyenin altına indiğinde önbelleğe alınmış bekleme belleğini temizler, oyunun bellek kümesini korur.
* **Tam Ekran İyileştirmesi (FSO) & DirectX Bağımsız Flip:** Pencereli tam ekran gecikmesini ortadan kaldıran bağımsız flip sunumunu (`SwapEffectUpgradeEnable=1`, `VRROptimizeEnable=1`) uygular ve GameDVR kaydını kapatır.

---

### 5. 🛡️ İşlemsel StateVault & Canlı Windows Doğrulama Motoru
* **Otomatik Fabrika Yedeklemesi:** İlk çalıştırmada makinenin orijinal fabrika değerlerini tespit eder ve `original_baseline_backup.txt` içine saklar.
* **Canlı Sistem Doğrulama (Live OS Verification):** Uygulanan ayarları anlık olarak kayıt defterinden, güç şemalarından ve çekirdek zamanlayıcısından sorgulayarak doğrular.
* **Yeniden Başlatma Farkındalığı:** Bilgisayar yeniden başlatıldığında ilgili ayarları otomatik olarak `✓ Doğrulandı (Restart Aktif)` şeklinde işaretler.
* **Tek Tıkla Fabrika Ayarlarına Dönüş:** Değiştirilen tüm kayıt defteri anahtarlarını, güç şemalarını ve netsh kurallarını tek bir hamlede orijinal haline döndürür.

---

### 6. 📊 Teşhis & Benchmark Test Paketi
* **Çekirdek Uyku Sapması (Jitter) Analizi:** 25 döngülü `Thread.Sleep(1)` uyanma sapmasını çekirdek zamanlayıcısına karşı test eder.
* **Çoklu Sunucu Ping & Jitter Testi:** Cloudflare ve Google DNS üzerinden canlı paket gidiş-dönüş süresi ve dalgalanma ölçümü.
* **İnteraktif Fare Polling (Hz) & Kare Süresi Ölçümü:** 1000Hz, 2000Hz, 4000Hz ve 8000Hz fareler için canlı yoklama sıklığı ve kuyruk taşması tespiti.
* **Canlı Görev Yöneticisi & Çekirdek Atama Tablosu:** Tek tıkla çekirdek atama (affinity), öncelik yükseltme ve EcoQoS kontrolü.

---

## 📁 Proje Dizin Yapısı

```
Argon-Latency-Software/
├── .gitignore               # C# ve Visual Studio hariç tutma kuralları
├── LICENSE                  # MIT Açık Kaynak Lisansı
├── README.md                # Türkçe Dokümantasyon & Mimari Kılavuzu
├── app.manifest             # Windows 10/11 Yüksek DPI ve Yönetici Uyumluluk Dosyası
├── ArgonLatencyStudio.csproj# MSBuild C# Proje Dosyası
├── ArgonLatencyStudio.sln   # Visual Studio Çözüm Dosyası
├── build.bat                # Sıfır bağımlılıklı yerleşik derleme scripti (csc.exe)
└── src/
    └── ArgonLatencyStudio.cs # Eksiksiz, tek parça C# kaynak kodu (~7.000 satır)
```

---

## 🔨 Derleme & Kaynaktan Çalıştırma

### Yöntem 1: Hızlı Derleme (IDE veya SDK Gerekmez)
`build.bat` dosyasına çift tıklayın veya PowerShell üzerinden çalıştırın:
```cmd
build.bat
```
*(Windows ile birlikte gelen yerleşik C# derleyicisini kullanır: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`)*

### Yöntem 2: Visual Studio (2019 / 2022)
1. `ArgonLatencyStudio.sln` çözüm dosyasını açın.
2. Üst menüden **Release | x64** seçin.
3. `Ctrl + Shift + B` tuşlarına basarak derleyin.

### Yöntem 3: Komut Satırından Doğrudan csc.exe İle
```powershell
& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:winexe /platform:x64 /optimize+ /out:"Argon_UltraLowLatency_v3.8.exe" /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Management.dll "src\ArgonLatencyStudio.cs"
```

---

## ⚠️ Güvenlik ve Sistem Bütünlüğü Garantisi
* **Hız Aşırtma / Voltaj Değişikliği Yok:** Yapılan tüm işlemler resmi Microsoft Windows API ve donanım üreticisi sürücü spesifikasyonları dahilindedir.
* **Sıfır Sistem Şişmesi:** Sisteme herhangi bir arka plan servisi veya zamanlanmış görev kurulmaz. Uygulama kapatıldığında yalnızca seçtiğiniz kayıt defteri ayarları aktif kalır.
* **%100 Geri Alınabilirlik:** İstediğiniz an **"Tümünü İlk Haline Döndür"** butonuna basarak tüm sistemi orijinal fabrika ayarlarına döndürebilirsiniz.
* **Dışarıdan bir istek alma-gönderme yoktur. Güncelleme olursa buradan manual olarak güncellenecektir**
* **Bazı antivirüs programları "!ML" (Machine learning) ve dwm.exe gibi kernel bileşenlerine müdehale edilebildiği için nadir de olsa bazı sistemlerde False Positive verebilir.**

---

## 📄 Lisans
Bu proje [MIT Lisansı](LICENSE) kapsamında açık kaynak olarak lisanslanmıştır.
