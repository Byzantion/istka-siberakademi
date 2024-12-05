# istka-siberakademi
İSTKA-İGÜ SİBER AKADEMİ PROJE
![Ekran görüntüsü 2024-11-25 120725](https://github.com/user-attachments/assets/33b9e3e0-8322-4e81-8f16-1f68957fca84)

# 🛡️ T-Pot ve Splunk ile Honeypot İzleme ve Saldırı Analizi

Bu proje, **T-Pot honeypot sistemi** ile **Splunk** arasında entegrasyon kurarak saldırı loglarının toplanmasını, analiz edilmesini ve görselleştirilmesini amaçlar. Proje kapsamında, hem yerel ağdaki hem de dışarıdan gelen saldırılar izlenmiş ve raporlanmıştır.

---

## 🚀 Proje Özeti

- **T-Pot**: Honeypot tabanlı güvenlik çözümü, sahte servisler aracılığıyla saldırı davranışlarını kaydeder.  
- **Splunk**: Saldırı loglarını JSON formatında alıp analiz ve görselleştirme sağlar.  
- **Amaç**: Saldırgan aktivitelerini izlemek, güvenlik açıklarını anlamak ve raporlamalar oluşturmak.  

---

## 📂 Kurulum Adımları

### 1️⃣ T-Pot Kurulumu

1. **T-Pot'u sunucuya yükleyin**:  
   [T-Pot Kurulum Dokümantasyonu](https://github.com/telekom-security/tpotce)

2. **Firewall yapılandırması**:  
   T-Pot'un dışarıdan saldırı alabilmesi için gerekli portları açın.

3. **Honeypot'u test edin**:  
   
2️⃣ Splunk Entegrasyonu
Splunk Sunucusunu Yapılandırın:
Splunk'ı kurun ve gerekli giriş ayarlarını yapın.

Splunk Kurulum Rehberi
JSON Loglarını Bağlayın:
T-Pot'un ürettiği logların Splunk'a yönlendirilmesini sağlayın.

Splunk Dashboard Oluşturun:
Saldırıları görselleştirmek için özel bir dashboard oluşturun.

🛠️ Saldırı Çeşitleri
1️⃣ Port Tarama (Port Scanning)
Amaç: T-Pot sistemine ait açık portları ve bu portlardaki hizmetleri tespit etmek.
Kullanılan Komut:
nmap -sS -sV -p 21,22,23 <t-pot_ip_adresi>

2️⃣ FTP Brute Force Saldırısı
Amaç: Hedef sistemin FTP servisine karşı kaba kuvvet saldırısı yapmak.
Komut:
hydra -L usernames.txt -P passwords.txt ftp://<t-pot_ip_adresi>

3️⃣ SSH Brute Force Saldırısı
Komut:
hydra -L usernames.txt -P passwords.txt ssh://<t-pot_ip_adresi>:22
Bu saldırı ile SSH servisinde kaba kuvvet denemeleri yapılmıştır.

4️⃣ HTTP Güvenlik Taraması (Nikto)
Komut:
nikto -h http://<t-pot_ip_adresi>
HTTP servisine yönelik tarama yapılmıştır.
Potansiyel güvenlik açıkları (ör. XSS, zayıf şifreleme) tespit edilmeye çalışılmıştır.

5️⃣ XSS Saldırısı
Komut:
wget http://<t-pot_ip_adresi>/jsp-examples/jsp2/el/implicit-objects.jsp?foo=<script>alert('XSS Saldırısı Alert Denemeleri!');</script>
Bir HTTP isteğiyle XSS açığı test edilmiştir.
Komut çalıştırıldığında potansiyel bir XSS açığı tetiklenmiştir.

1. Sistem Mimarisi Diyagramı
![2](https://github.com/user-attachments/assets/22198153-53e9-4e2d-b8c6-ecba20e34544)
Saldırgan: İç veya dış kaynaklardan gelen tehdit aktörlerini temsil eder.
T-Pot Honeypot Sistemi: Saldırıları tespit eder ve loglar.
Splunk Sunucusu: T-Pot’tan gelen logları analiz eder ve raporlar.

2. Saldırı Türleri ve Tespit Süreci
![1](https://github.com/user-attachments/assets/2cd175a4-0cfb-4174-82d1-a774dfebbd1c)
Her bir saldırı türü, T-Pot honeypot sistemi tarafından algılanır ve analiz edilir.
NMAP, Hydra, Nikto ve XSS gibi araçlar farklı saldırı türlerini temsil eder.

📊 Çıktılar
T-Pot ve Splunk üzerinde kaydedilen loglar ve raporlar:


EN SON ORANGE, PYTHON YANI AI KISMI GELECEK !!!












