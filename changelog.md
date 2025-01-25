# Changelog

## [0.5.0] - 2024-01-25

### Eklendi
- SSL/TLS analiz modülü (ssl_analyzer.py) eklendi
  - Sertifika analizi
  - Protokol desteği kontrolü
  - Cipher suite analizi
  - Güvenlik seviyesi değerlendirmesi
  - Öneriler ve iyileştirmeler
- Ana programa SSL/TLS analizi entegre edildi
- Detaylı SSL/TLS raporu çıktısı eklendi
- Yeni bağımlılıklar eklendi:
  - cryptography>=42.0.5
  - pyOpenSSL>=24.0.0

## [0.4.0] - 2024-01-25

### Eklendi
- JavaScript analiz modülü (js_analyzer.py) eklendi
  - Popüler JS kütüphanelerinin versiyon tespiti
  - Güvenlik riski içeren kod pattern'larının tespiti
  - API endpoint'lerinin çıkarılması
  - Script boyut analizi
  - Minified kod tespiti
- Ana programa JavaScript analizi entegre edildi
- Detaylı JavaScript raporu çıktısı eklendi

## [0.3.0] - 2024-01-25

### Eklendi
- Zafiyet tarayıcı modülü (vulnerability_scanner.py) eklendi
  - NVD API entegrasyonu
  - Teknoloji bazlı zafiyet taraması
  - CVE detayları ve CVSS skorları
  - Zafiyet cache sistemi
- Ana programa zafiyet tarama entegre edildi
- Zafiyet raporu çıktısı eklendi

## [0.2.0] - 2024-01-24

### Eklendi
- CMS dedektör modülü (cms_detector.py) eklendi
  - WordPress, Joomla ve Drupal CMS tespiti
  - Versiyon tespiti
  - Path tabanlı kontroller
  - Meta tag analizi
  - Cookie analizi
- Ana programa CMS tespiti entegre edildi
- Detaylı CMS raporu çıktısı eklendi

## [0.1.0] - 2024-01-23

### Eklendi
- Proje başlatıldı: "Web Teknoloji Parmak İzi Çıkarma"
- Temel proje yapısı oluşturuldu
- Changelog.md dosyası eklendi
- requirements.txt dosyası oluşturuldu ve gerekli bağımlılıklar eklendi
- README.md dosyası oluşturuldu
- Ana program dosyası (main.py) oluşturuldu
  - HTTP header analizi özelliği
  - JavaScript kütüphane tespiti
  - Wappalyzer entegrasyonu
  - Asenkron tarama desteği
  - Renkli terminal çıktısı
  - JSON formatında rapor kaydetme
  - Güvenlik başlıkları kontrolü

### Hedefler
- SSL/TLS analizi eklenmesi 