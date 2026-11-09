# Argon Latency Studio v4.0

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%20Windows%2011%20x64-0078D6?logo=windows)](https://microsoft.com)
[![Runtime](https://img.shields.io/badge/Runtime-.NET%20Framework%204.8%20%7C%20C%23-239120?logo=c-sharp)](https://docs.microsoft.com/dotnet/csharp/)
[![Doğrulama](https://img.shields.io/badge/Do%C4%9Frulama-Live%20OS%20Truth%20%26%20StateVault-10B981)](#-mimari-ve-temel-yetenekler)
[![Dil Desteği](https://img.shields.io/badge/Dil-T%C3%BCrk%C3%A7e%20%7C%20English-blue)](#-aray%C3%BCz-ve-kullan%C4%B1c%C4%B1-deneyimi)
[![Lisans](https://img.shields.io/badge/Lisans-MIT-yellow.svg)](LICENSE)

**Argon Latency Studio**, Windows işletim sistemlerinde gecikme hassasiyeti yüksek rekabetçi oyunlar ve düşük gecikmeli ağ senaryoları için geliştirilmiş açık kaynaklı bir performans, telemetri ve sistem optimizasyon stüdyosudur.

Uygulama; arka planı belirsiz toplu kayıt defteri betikleri yerine, her bir sistem ayarını özgün Windows API'leri üzerinden denetleyen, donanım mimarisine duyarlı çalışan ve **StateVault** mekanizmasıyla işlemsel olarak geri alınabilir kılan doğrulanabilir bir altyapı sunar.

> **Gözlemlenen Performans:** Test ortamlarında (ör. *Path of Exile*, *Counter-Strike 2*) termal değerler korunarak %3 – %5 aralığında ortalama FPS iyileşmesi ve %1 / %0.1 Low kare süresi (frame-time) tutarlılığı raporlanmıştır. Bu değerler referans niteliğinde olup donanım kombinasyonuna ve işletim sistemi sürümüne göre farklılık gösterebilir.

---

## 🔬 Mimari ve Temel Yetenekler

### 1. Gerçek Sistem Durumu Doğrulaması (Live OS Truth) & StateVault
* **Okuma ve Doğrulama:** Arayüz soyut durum bayraklarına değil; Windows Kayıt Defteri, Güç Politikası (`powrprof.dll`), Win32 SPI parametreleri ve NT Çekirdek API'leri üzerinden canlı okunan değerlere dayanır.
* **Deterministik Geri Alma:** İlk çalıştırmada işletim sisteminin fabrika parametreleri yakalanır (`StateVault`). "Fabrika Ayarlarına Dön" işlemiyle tüm parametreler doğrulanarak orijinal durumuna geri döndürülür.

### 2. NT Çekirdek Zamanlayıcısı (Kernel Timer Resolution Engine)
* **Yüksek Çözünürlüklü Modlar:** 0.500 ms (Ultra Düşük Gecikme), 0.504 ms (AMD Ryzen P-State senkronu) ve 1.000 ms (Fare / HID senkron modu) seçenekleri.
* **Çoklu Süreç İzolasyonu:** Harici bir sürecin işletim sistemi genelinde daha düşük çözünürlük talep ettiği senaryolar tespit edilir; uygulanan hedef değer ile aktif işletim sistemi minimumu bağımsız olarak raporlanır.

### 3. Donanım Duyarlı Matris & LibreHardwareMonitor Telemetrisi
* **Mimariler:** AMD Ryzen / X3D (EPP & PBO dengesi), Intel Hibrit P+E (performans çekirdeği optimizasyonu), AMD Radeon (ULPS ve derin uyku denetimi) ve NVIDIA GeForce profil desteği.
* **Sensör İzleme:** Entegre `LibreHardwareMonitorLib` ile CPU çekirdek sıcaklığı, GPU çekirdek/hotspot sıcaklıkları, GPU yükü ve bellek (VRAM) kullanımının gerçek zamanlı takibi.

### 4. Ağ ve TCP/IP Yığın Yönetimi
* Nagle algoritması denetimi (TCP_NODELAY), Winsock AFD Fast-Path, RTO optimizasyonu, DSCP/QoS etiketlemesi ve ağ bağdaştırıcısı kesme dengelemesi (Interrupt Moderation).
* Canlı ağ trafiği, DNS önbellek yönetimi ve çift yönlü ICMP/RTT ölçümü.

### 5. Makineye Özel Parametre Mimarisi & Kesin HID Güvenlik Kilidi
* **Kullanıcı Tanımlı Değişkenler:** Sabit ön ayar modlarının yanında kullanıcının kendi donanımına ve bağlantısına özel değer girmesine imkan tanıyan `[⚙]` modal ayar paneli ve `NumericUpDown` mimarisi.
* **Kesin Güvenlik Sınırı (HID Buffer Guard):** `MouseDataQueueSize` ve `KeyboardDataQueueSize` ayarlarında 32'nin altındaki değerler kesinlikle engellenir ve uygulanmaz. Bu kural, 1000Hz – 8000Hz espor farelerinde anlık CPU yükünde oluşabilecek tampon taşmasını (buffer overrun), imleç takılmasını ve girdi kaybını önler.
* **Engelleme ve Rehberlik Deneyimi:** Güvenlik tabanı altındaki değerlerde teknik gerekçeli güvenlik penceresi açılır; doğrudan `HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters` yolunu açan `Kayıt Defterinde Aç (Regedit)` ve `"Mouse - Keyboard Queue size ayarlama"` sorgusunu açan `Google'da Ara` butonları sunulur.
* **Genişletilmiş Ağ Parametreleri:** TCP İlk Kayıp Paket Telafi Süresi (`NET_RTO`, 300ms protokol tabanı korumalı) ve Ağ Kartı Rx/Tx Ring Buffers (`NET_NIC_INT`, 64 paket taban korumalı) ayarları da aynı güvenlik ve yönlendirme mimarisiyle donatılmıştır.

### 6. Otomasyon & Yaşam Kalitesi (QoL)
* **Akıllı Güç Zamanlayıcısı:** Geri sayım veya belirli saatte kapatma, yeniden başlatma, uyku veya oturum kilitleme. Aktif ağ indirmeleri algılandığında işlemi otomatik erteleme koruması.
* **Periyodik Kripto & Rutin Alarmları:** 4 saatlik mum kapanışları, günlük/haftalık kapanışlar veya özel periyotlar için sesli (WAV/MP3) ve masaüstü bildirimleri.
* **Oyun İçi Not Kalkanı:** Belirlenen oyun süreçleri (`.exe`) başlatıldığında sessiz masaüstü bilgi kartları sunma.
* **Bellek & Standby List Otomasyonu:** Yapılandırılabilir eşik değerleri (%10, %15, %20 veya serbest değer) üzerinden otomatik arka plan bellek optimizasyonu.

### 7. Arayüz ve Çoklu Dil Desteği
* Dinamik Türkçe ve İngilizce dil desteği (üst çubuktan veya ayarlardan anlık geçiş).
* Arayüz taşmalarını önleyen sabit geometri seçenekleri (Kompakt 1280x820, Standart 1380x890, Geniş 1560x960).
* Başlık, açıklama, teknik gerekçe ve kayıt anahtarlarını kapsayan birleşik genel arama (Global Search).
* Headless test ve otomatik UI doğrulama için `--render-ui` komut satırı desteği.

---

## 📋 Modül Yapısı (11 Sekme)

| Sekme | Kapsam ve Açıklama |
| :--- | :--- |
| **Donanım (Hardware)** | AMD CPU, Intel CPU, AMD GPU ve NVIDIA GPU mimari optimizasyon matrisi. |
| **Ağ (Network)** | TCPACKFrequency, TCPNoDelay, NetAdapter offload ayarları ve Winsock yapılandırması. |
| **Timer** | NT Timer resolution, Win32 Quantum, C-States, çekirdek park etme ve HID kuyruk boyutu. |
| **Grafik (Graphics)** | DWM Multiplane Overlay (MPO), FSO, DXGI flip modeli ve EcoQoS yapılandırması. |
| **Sistem (System)** | Güvenli ChrisTitusTech/winutil türevi sistem ayarları, hazırda bekletme ve IPv4 önceliklendirmesi. |
| **Kernel** | Sentetik darbe thread'i (Anti-C1E), SMT mantıksal çekirdek izolasyonu ve TCP congestion sağlayıcıları. |
| **İşlemler (Processes)** | Çalışan süreçlerin CPU önceliği, çekirdek ataması (Affinity) ve bellek izlemesi. |
| **Otomasyon (Automation)** | Güç zamanlayıcısı, periyodik kripto/rutin alarmları, oyun notları ve bellek otomasyonu. |
| **Tanı Test (Diagnostics)** | 25 iterasyonlu NT Sleep kararlılık analizi, çift hedefli Ping RTT testi ve HID yoklama ölçümü. |
| **Günlük (Event Log)** | İşlem günlüğü, oturum bildirimleri ve StateVault durum denetim kayıtları. |
| **Ayarlar (Settings)** | Sensör yoklama sıklığı, pencere geometrisi, özel profil yönetimi (`.argon`) ve dil seçimi. |

---

## 🛠️ Derleme ve Çalıştırma

Proje, harici bir paket yöneticisi gerektirmeksizin Windows üzerinde standart Microsoft .NET Framework derleyicisi ile derlenebilir:

```cmd
build.bat
```

Derleme işlemi sonrasında çalıştırılabilir dosya doğrudan üretilir:
`bin\Release\Argon_UltraLowLatency_v4.0.exe`

Visual Studio kullanıcıları `ArgonLatencyStudio.sln` çözümünü açarak **Release | x64** hedefiyle derleyebilir.

---

## 🛡️ Güvenlik ve Sistem Bütünlüğü

* **Donanım Koruması:** Donanım saat frekansları veya voltaj parametreleri değiştirilmez.
* **Güvenlik Katmanlarına Müdahale Edilmez:** Windows Defender, SmartScreen veya güvenlik duvarı gibi kritik sistem servisleri devre dışı bırakılmaz.
* **Tam Geri Alınabilirlik:** Yapılan her değişiklik `StateVault` günlüğünde kayıt altına alınır ve istenildiği anda fabrika değerlerine döndürülebilir.

---

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) kapsamında sunulmaktadır.
