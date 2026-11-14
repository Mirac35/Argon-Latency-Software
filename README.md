# Argon Latency Studio

Windows 10 ve Windows 11 için tek pencerede sistem bilgisi, düşük gecikme ayarları, Windows özelleştirmeleri ve pratik otomasyon araçları sunan masaüstü yardımcı programı.

Argon, sistemde ne değiştirdiğini gizleyen toplu kayıt defteri betikleri yerine **StateVault** yapısıyla çalışır: her ayarın özgün değerini uygulamadan önce kaydeder, sonucu doğrudan Windows üzerinden okuyarak doğrular ve istediğiniz an tek tıkla başlangıç durumuna döndürür.

---

## Neler Yapabilirsiniz?

### Sisteminizi ve Canlı Sensörleri İzleyin
- İşlemci, ekran kartı, bellek modülleri (DIMM), anakart, BIOS, disk ve ekran çıkışlarını donanım özeti ekranında görün.
- Entegre `LibreHardwareMonitorLib` ile çekirdek sıcaklıklarını, yük oranlarını, VRAM kullanımını ve canlı ağ gecikmesini (Ping / DNS) takip edin.

### Performans ve Düşük Gecikme Ayarlarını Yönetin
- Donanım mimarinize göre (AMD Ryzen / Radeon, Intel, NVIDIA) hazırlanmış profiller arasında geçiş yapın.
- Çekirdek zamanlayıcısı (`0.500 – 1.000 ms`), TCP/IP ve ağ bağdaştırıcısı parametreleri, grafik sunumu (MPO / DXGI), güç planı ve oyun/süreç önceliklerini kontrol edin.
- Her parametre için makinenize özel değer girin; yüksek polling oranlı fare/klavye kuyruklarında taşmayı önleyen dahili güvenlik sınırları hatalı değerlere izin vermez.

### Linux Benzeri Orta Tuş Kaydırma (1:1 Akıcı Kaydırma)
- Fare tekerleğini döndürmek yerine orta tuşa (veya seçtiğiniz yan tuşa) basılı tutup fareyi oynatarak tüm pencerelerde dikey ve yatay 1:1 kaydırma yapın.
- Tek kısa basışta normal orta tık işlevi korunur; yön eşiği, hız/hassasiyet ve doğal kaydırma seçenekleri doğrudan arayüzden ayarlanabilir.

### Windows Özelleştirmelerini Tek Yerden Düzenleyin
- Klasik sağ tık menüsü, görev çubuğu düzeni, Dosya Gezgini davranışları, gizlilik tercihleri ve sistem kısayollarını kategorize ağaç menüden açıp kapatın.
- Sık kullandığınız ayarları **Yer İmleri** altında toplayın ve koyu/açık tema ile Türkçe/İngilizce arayüz arasında anında geçiş yapın.

### Otomasyon ve Tanılama Araçlarını Kullanın
- **Otomasyon:** Aktif indirmeleri algılayıp erteleyebilen kapatma/uyku zamanlayıcısı, periyodik alarmlar, oyun içi sessiz not kartları ve eşik bazlı Standby RAM temizliği.
- **Tanılama:** Zamanlayıcı sapma testi, çift hedefli Ping ölçümü, Raw Input (`WM_INPUT`), USB/PCIe MSI kesme yöneticisi ve sanal bellek (Pagefile) analiz araçları.

---

## Güvenlik ve Şeffaflık

- **Geri Alınabilirlik:** Uygulanan tüm kayıt defteri ve güç ayarları StateVault günlüğünde saklanır; *Fabrika Sıfırla* ile eski haline döndürülebilir.
- **Sınırlar:** Windows Defender, güvenlik duvarı, SmartScreen veya donanımsal termal/voltaj korumalarına dokunulmaz.
- **Performans Notu:** Seçili bir profille sahibinin test makinesinde sıcaklıklar korunarak %3–5 FPS artışı gözlemlenmiştir; kazanç donanıma ve oyuna göre değişebilir.

---

## Derleme ve Çalıştırma

Harici paket yöneticisi gerekmez. Depo kök dizininde Windows .NET Framework 4.8 derleyicisiyle doğrudan derleyebilirsiniz:

```cmd
build.bat
```

Çıktı olarak kök dizinde `Argon_UltraLowLatency_v4.0.exe` oluşur (bağımlı kütüphaneler `lib\` klasöründen yüklenir). Visual Studio ile `ArgonLatencyStudio.sln` üzerinden **Release | x64** olarak da derlenebilir.

> **Not:** Çekirdek zamanlayıcısı, kayıt defteri ve güç planı değişiklikleri için yönetici yetkisi gerekir; salt donanım izleme ve kaydırma özellikleri standart kullanıcıda da çalışır.

---

## Lisans

Bu proje [MIT Lisansı](LICENSE) altında sunulmaktadır.
