# ⚡ Argon Düşük Gecikme & TCP Optimizer Studio (v4.0 - 2026 Edition)

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%20Windows%2011-0078D6?logo=windows)](https://microsoft.com)
[![Dil](https://img.shields.io/badge/Dil-C%23%205.0%20%2F%20.NET%204.0+-239120?logo=c-sharp)](https://docs.microsoft.com/dotnet/csharp/)
[![Canlı-OS-Doğrulama](https://img.shields.io/badge/Do%C4%9Frulama-Ger%C3%A7ek%20Durum%20(Live%20OS%20Truth)-10B981)](#-1-ger%C3%A7ek-durumdan-t%C3%BCretilen-alg%C4%B1lama-motoru-live-os-truth)
[![Güvenlik](https://img.shields.io/badge/G%C3%BCvenlik-S%C4%B1f%C4%B1r%20Debloat%20%2F%20Defender%20Korumal%C4%B1-blue)](#-g%C3%BCvenlik-ve-sistem-b%C3%BCt%C3%BCnl%C3%BC%C4%9F%C3%BC-garantisi)
[![Lisans: MIT](https://img.shields.io/badge/Lisans-MIT-yellow.svg)](LICENSE)

**Argon Latency Studio v4.0**, rekabetçi espor oyunları (*Path of Exile 2, CS2, Valorant, Apex Legends, Fortnite, League of Legends*) ve düşük gecikmeli P2P / WebRTC ağ protokolleri (*HaxBall* vb.) için 2026 standartlarında baştan aşağı yenilenmiş, **canlı işletim sistemi algılamalı (Live OS Truth)**, **LibreHardwareMonitor telemetrili** ve **kademeli donanım duyarlı** sistem/ağ optimizasyon stüdyosudur.

PoE 2 ve CS2 gibi yoğun işlemci ve girdi hassasiyeti gerektiren modern oyunlarda yapılan testlerde **%3 - %5 net ortalama FPS artışı** ve belirgin **%1 / %0.1 Low kare süresi (frame-time) kararlılığı** sağlar.

---

## 🌟 2026 Sürümüyle Gelen Yenilikler (v4.0)

### 1. 🔍 Gerçek Durumdan Türetilen Algılama Motoru (Live OS Truth)
Eski sürümlerdeki kayıtlı bayraklara dayalı sistem tamamen kaldırıldı. Artık arayüzdeki hiçbir ayar soyut bayraklara güvenmez:
* **Canlı OS Sorgulaması:** Windows Kayıt Defteri (Registry), Güç Planı (`powrprof.dll`), Win32 SPI (`user32.dll`) ve Çekirdek Zamanlayıcısı (`ntdll.dll`) anlık olarak taranır.
* **Sıfırlama Sonrası Sıfır Hata:** "Makine Varsayılanlarına Döndür" (Reset) yapıldığında veya dışarıdan bir ayar değiştirildiğinde, gerçek sistem durumu anında tespit edilir ve arayüzle senkronize olur; **görsel bug'lar (visual bugs) tamamen engellenir**.
* **Tek Tıkla Gerçek Durumu Eşitleme:** Üst bardaki `🔄 Gerçek Durumu Algıla` butonuyla, sistemde halihazırda aktif olan tüm ayarlar tek tıkla arayüz anahtarlarına yansıtılır.

### 2. 🌡️ LibreHardwareMonitor Canlı Donanım Telemetrisi
Sisteminizi zorlamadan, arka planda sıfır gecikmeyle donanım sağlığını takip eden entegre telemetri motoru:
* **İşlemci (CPU):** Canlı Sıcaklık (`Core Tctl/Tdie`) ve Toplam Yük (`%`).
* **Ekran Kartı (GPU):** **Core Sıcaklığı**, **Memory (VRAM) Sıcaklığı**, **Hotspot Sıcaklığı**, **GPU Çekirdek Yükü (`%`)** ve **VRAM Kullanımı (MB)**.
* **Özelleştirilebilir:** İstenilen sensör `⚙️ Ayarlar` sekmesinden kapatılabilir veya yoklama sıklığı (500ms / 1s / 2s) ayarlanabilir.

### 3. 📐 Sabit, Kompakt ve Profesyonel Arayüz Düzeni
* Varsayılan olarak **1240x880 sabit geometri** (`FormBorderStyle.FixedSingle`, `MaximizeBox = false`) ile çalışır. Elementlerin veya kartların pencere boyutu nedeniyle kayması, üst üste binmesi kesinlikle engellenmiştir.
* Esnek pencere tercih eden kullanıcılar için `⚙️ Ayarlar` üzerinden boyutlandırılabilir mod açılıp kapatılabilir.

### 4. 🔎 Tüm Sekmelerde Gerçek Genel Arama (Global Search)
* Hangi sekmede olursanız olun arama kutusuna yazmaya başladığınız anda **Donanım, Network, Latency, FPS, WinUtil ve Deneysel** dahil tüm sekmelerdeki 45 ayar aynı anda taranır.
* Başlık, açıklama, teknik neden, kayıt defteri konumu ve alt mod isimleri tek bir birleşik sonuç ekranında toplanır; arama temizlendiğinde tüm kartlar kendi sekmelerine döner.

### 5. 💾 İsimlendirilebilir Özel Profil Yönetimi (Named Profiles)
* Hazır espor profillerinin yanı sıra kendi açık ayarlarınızı istediğiniz isimle (`.argon` formatında) kaydedebilirsiniz.
* Üst bardaki **💾 Profil** açılır menüsünden tek tıkla profiller arasında geçiş yapabilir, profilleri silebilir veya başka bilgisayarlara dışa/içe aktarabilirsiniz.

### 6. 🛡️ ChrisTitusTech/winutil Güvenli Mimari Seçkisi & Kritik Onay Sistemi
* [ChrisTitusTech/winutil](https://github.com/ChrisTitusTech/winutil) projesinden seçilen 7 adet güvenli, yüksek etkili mimari ayar:
  * `WU_MPO_CONTROL`: DWM Multiplane Overlay (MPO) Titreme & Stutter Kalkanı
  * `WU_IPV4_TEREDO`: IPv4 Önceliklendirme & Teredo Gecikme Kalkanı
  * `WU_DELIVERY_OPT`: Windows Update P2P Arka Plan Yükleme Kalkanı
  * `WU_HIBERNATION`: Hazırda Bekletme (`hiberfil.sys`) & Hızlı Başlatma Kontrolü
  * `WU_WPBT_COMPANION`: BIOS WPBT Enjeksiyon Kalkanı & Ağ Üzerinden Cihaz Meta Verisi Engelleme
  * `WU_UX_PRO_TOOLS`: Görev Çubuğundan "Görevi Sonlandır" & Yapışkan Tuş Kalkanı
  * `WU_GAMEMODE_STORAGE`: Otomatik Oyun Modu & Disk Akıllı Depolama Tarama Kalkanı
* **Güvenlik Politikası:** Kesinlikle hiçbir debloating yapılmaz; Windows Defender, güvenlik duvarı veya kritik sistem bileşenleri asla kapatılmaz.
* **Kritik Onay & Geri Yükleme:** Kritik ayarlar uygulanmadan önce teknik onay penceresi açılır ve tek tıkla **Windows Sistem Geri Yükleme Noktası** (`System Restore Point`) oluşturulabilir.

---

## 🏛️ Argon Modül Haritası (10 Standart Sekme)

| Sekme | İkon | Modül Sayısı | Açıklama |
| :--- | :---: | :---: | :--- |
| **Donanım Matrisi** | 🤖 | 5 | AMD Ryzen/X3D, Intel Core/Hibrit P+E, NVIDIA GeForce, AMD Radeon ve Intel Arc mimari optimizasyonları |
| **Network & TCP** | 🌐 | 12 | Çift katmanlı Nagle iptali, Winsock AFD Fast-Path, RTO 300ms, TCP 1323, NIC IntMod=0, DSCP QoS |
| **Latency & Kernel** | ⏱️ | 9 | 0.500ms (2000Hz) Kernel Timer kilidi, Win32 Quantum, C-States, 1:1 Raw Mouse, DataQueueSize, Sessiz FilterKeys |
| **FPS & GPU** | 🚀 | 9 | EcoQoS Arka Plan Kafesi, audiodg.exe Çekirdek 0 İzolasyonu, FSO & DXGI Independent Flip, HAGS, Canlı Servis Askıya Alma |
| **WinUtil & Kritik** | 🛡️ | 7 | MPO kontrolü, IPv4 önceliği, P2P yükleme engelleme, WPBT kalkanı, Hibernation ve Oyun Modu kilitleri |
| **Deneysel Motor** | 🧪 | 8 | SerializeTimer, Sentetik Mikro-Sinyal (Anti-C1E), SMT İzolasyonu, TCP Cubic/BBR, SvcHost Split |
| **Süreç & Çekirdek** | 🎯 | - | Çalışan oyun ve uygulamalara canlı CPU önceliği (High Priority), Çekirdek Maskeleme (Affinity) ve EcoQoS kalkanı |
| **Benchmark & Test** | 📊 | - | 25 iterasyonlu Kernel Sleep(1) Jitter Testi, Cloudflare/Google Çift Ping Analizi, 8000Hz Canlı Fare Polling Testi |
| **Yedek & Canlı OS** | 🔍 | - | StateVault tam geri yükleme günlüğü ve her ayarın açılış öncesi/sonrası gerçek Windows değerleri tablosu |
| **Program Ayarları** | ⚙️ | - | Telemetri sensör anahtarları, sabit pencere kilidi, zengin tooltip yönetimi, özel profil kaydetme ve içe/dışa aktarma |

---

## 📁 Proje Dizin Yapısı

```
Argon-Latency-Software/
├── .gitignore               # Visual Studio, C# ve kullanıcı profil hariç tutma kuralları
├── LICENSE                  # MIT Açık Kaynak Lisansı
├── README.md                # Kapsamlı Dokümantasyon & Kullanıcı Kılavuzu
├── app.manifest             # Windows 10/11 Yüksek DPI ve Yönetici Uyumluluk Dosyası
├── ArgonLatencyStudio.csproj# MSBuild C# Proje Dosyası
├── ArgonLatencyStudio.sln   # Visual Studio Çözüm Dosyası
├── build.bat                # Hızlı yerleşik derleyici betiği (csc.exe)
├── lib/                     # LibreHardwareMonitorLib ve donanım kütüphaneleri
│   ├── LibreHardwareMonitorLib.dll
│   ├── HidSharp.dll
│   ├── BlackSharp.Core.dll
│   ├── DiskInfoToolkit.dll
│   ├── RAMSPDToolkit-NDD.dll
│   └── System.*.dll
└── src/
    └── ArgonLatencyStudio.cs # Tam teşekküllü, sıfır visual-bug C# kaynak kodu (~10.300 satır)
```

---

## 🔨 Derleme & Kaynaktan Çalıştırma

### Yöntem 1: Tek Tıkla Derleme (Önerilen)
Harici bir SDK veya Visual Studio kurulumuna ihtiyaç duymadan, Windows ile gelen yerleşik derleyici ile derlemek için:
```cmd
build.bat
```
Betik, `lib/` klasöründeki bağımlılıkları otomatik kopyalar ve doğrudan `bin\Release\ArgonLatencyStudio.exe` dosyasını üretir.

### Yöntem 2: Visual Studio (2019 / 2022)
1. `ArgonLatencyStudio.sln` çözüm dosyasını açın.
2. Üst araç çubuğundan **Release | x64** yapılandırmasını seçin.
3. `Ctrl + Shift + B` tuşlarına basarak derleyin.

---

## ⚠️ Güvenlik ve Sistem Bütünlüğü Garantisi

* **Hız Aşırtma / Voltaj Riski Yok:** Program donanım voltajlarını veya saat hızlarını değiştirmez. Yalnızca resmi Microsoft Windows çekirdek API'leri ve sürücü standartları üzerinden çalışır.
* **Sıfır Debloat & Sıfır Şüpheli Kod:** Windows Defender, SmartScreen veya güvenlik duvarı gibi koruma katmanlarına asla dokunulmaz.
* **İşlemsel StateVault ile %100 Geri Alınabilirlik:** İlk açılışta sisteminizin fabrika değerleri öğrenilir. Üst bardaki **"Makine Varsayılanlarına Döndür"** butonuna basıldığında tüm ayarlar canlı OS seviyesinde denetlenerek %100 orijinal haline döndürülür.

---

## 📄 Lisans
Bu proje [MIT Lisansı](LICENSE) kapsamında açık kaynak olarak lisanslanmıştır.
