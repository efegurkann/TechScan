# Web Teknoloji Parmak İzi Çıkarma Aracı

Bu araç, web uygulamalarında kullanılan teknolojileri tespit eden, sürüm bilgilerini çıkaran ve olası güvenlik açıklıklarını belirleyen kapsamlı bir analiz sistemidir. Modern web teknolojilerinin tespiti, güvenlik değerlendirmesi ve detaylı raporlama özellikleri ile güvenlik uzmanları ve web geliştiricileri için güçlü bir araç sunar.

## 🚀 Özellikler

### Teknoloji Tespiti
- Web framework ve CMS sistemlerinin otomatik tespiti
- JavaScript kütüphane ve framework analizi
- Sunucu teknolojileri ve altyapı bileşenlerinin tespiti
- Versiyon bilgisi çıkarma ve karşılaştırma

### Güvenlik Analizi
- HTTP güvenlik başlıklarının detaylı analizi
- SSL/TLS yapılandırma ve sertifika kontrolü
- Bilinen güvenlik açıklıklarının tespiti (CVE bazlı)
- JavaScript kod güvenliği analizi
- CMS ve framework güvenlik değerlendirmesi

### Performans ve Esneklik
- Asenkron tarama desteği ile hızlı analiz
- Paralel istek yönetimi
- Özelleştirilebilir timeout ve retry mekanizmaları
- Düşük sistem kaynağı kullanımı

### Raporlama
- Detaylı JSON formatında çıktı
- Renkli terminal görüntüleme
- Özelleştirilebilir rapor formatları
- Güvenlik önerileri ve iyileştirme tavsiyeleri

## 📋 Gereksinimler

- Python 3.8 veya üzeri
- pip (Python paket yöneticisi)
- İnternet bağlantısı

## 🛠️ Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/kullanici/web-tech-fingerprinter.git
cd web-tech-fingerprinter
```

2. Sanal ortam oluşturun ve aktive edin:
```bash
python -m venv venv
# Windows için
venv\Scripts\activate
# Linux/Mac için
source venv/bin/activate
```

3. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

## 💻 Kullanım

https://github.com/efegurkann/TechScan/raw/main/video/usage.mp4

### Temel Kullanım

```bash
python main.py -u https://example.com
```

### Tüm Parametreler

```bash
python main.py [-h] -u URL [-o OUTPUT] [-t TIMEOUT] [-v]

Argümanlar:
  -h, --help            Yardım mesajını göster
  -u URL, --url URL     Taranacak URL (zorunlu)
  -o OUTPUT, --output OUTPUT
                        Çıktı dosyası (varsayılan: output.json)
  -t TIMEOUT, --timeout TIMEOUT
                        İstek zaman aşımı (varsayılan: 30 saniye)
  -v, --verbose         Detaylı çıktı modu
```

### Örnek Kullanımlar

1. Basit tarama:
```bash
python main.py -u https://example.com
```

2. Detaylı çıktı ile tarama ve JSON rapor oluşturma:
```bash
python main.py -u https://example.com -v -o rapor.json
```

3. Özel timeout değeri ile tarama:
```bash
python main.py -u https://example.com -t 60
```

## 📊 Çıktı Formatı

Araç, aşağıdaki bilgileri içeren detaylı bir JSON raporu üretir:

- Temel URL ve tarama zamanı
- HTTP başlıkları ve güvenlik yapılandırması
- Tespit edilen teknolojiler ve versiyonları
- JavaScript kütüphaneleri ve güvenlik riskleri
- SSL/TLS analizi ve sertifika bilgileri
- CMS bilgileri ve sürüm detayları
- Potansiyel güvenlik açıklıkları
- Güvenlik önerileri

## 🔒 Güvenlik Notları

- Aracı yalnızca yetkili olduğunuz sistemlerde kullanın
- Üretim sistemlerinde dikkatli kullanın, yoğun taramalar performans etkisi yaratabilir
- API anahtarları ve hassas bilgileri güvenli şekilde saklayın
- Rate limiting ve request throttling özelliklerini kullanın

## 🤝 Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/YeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik: XYZ'`)
4. Branch'inizi push edin (`git push origin feature/YeniOzellik`)
5. Pull Request oluşturun

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 📧 İletişim

- Proje Sahibi: [Efe Gürkan] 