# Business Logic Vulnerabilities (İş Mantığı Zafiyetleri)

## Giriş

Business Logic Vulnerabilities (İş Mantığı Zafiyetleri), web uygulamalarının tasarım ve iş mantığındaki kusurlardan kaynaklanan güvenlik zafiyetleridir. Bu tür zafiyetler, uygulamanın beklenmeyen davranışlar sergilemesine ve saldırganların sistemi kötüye kullanmasına olanak sağlar.

### Temel Kavramlar

**İş Mantığı Nedir?**
- Uygulamanın gerçek dünya süreçlerini modelleyen kurallar bütünü
- Kullanıcının neleri yapabileceği, nasıl yapabileceği konusundaki tanımlar
- Sistem davranışlarını kontrol eden algoritmalar

**Zafiyet Türleri:**
- Yetersiz doğrulama kontrolları
- Mantıksal akış hatası
- Güven modeli problemleri
- İş kurallarının atlatılması

## Lab 1: Excessive Trust in Client-Side Controls

### Senaryo Açıklaması
Bu laboratuvarda, e-ticaret uygulaması ürün fiyatları konusunda client-side kontrole aşırı güven duymaktadır. Kullanıcının 100$ bütçesi bulunmakta ve normalde alamayacağı pahalı ürünleri satın alması beklenmektedir.

### Zafiyet Analizi

**Problem:** 
- Ürün fiyatı client tarafından (frontend) gönderilmekte
- Server-side'da fiyat doğrulaması yapılmamakta  
- Ürün ID ve miktar yerine kullanıcıdan fiyat bilgisi alınmakta

![HTTP Request Örneği](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/5c1a289a-8c23-461a-b939-cd8a61e8548d)

**HTTP Request Analizi:**
```http
POST /cart HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=1&quantity=1&price=133700
```

### Saldırı Tekniği

1. **Fiyat Manipülasyonu:** 
   - Orijinal fiyat: $1337.00
   - Manipüle edilen fiyat: $1.00 (sondaki iki hane ondalık kısım)

2. **Decimal İşleme:**
   - Uygulama sondaki 2 haneli sayıyı ondalık sonrası olarak kabul ediyor
   - 133700 → $1.00 şeklinde işleniyor

### Güvenlik Etkileri

- **Finansal Kayıp:** Ürünler gerçek fiyatından çok düşük fiyata satılabilir
- **Stok Yönetimi:** Hatalı fiyatlandırma stok takibini etkiler  
- **İş Süreci Bozulması:** E-ticaret süreçleri manipüle edilebilir

### Çözüm Önerileri

1. **Server-Side Validation:** Tüm fiyat bilgileri server tarafında saklanmalı
2. **Database Normalization:** Fiyatlar veritabanından çekilmeli
3. **Input Validation:** Client'dan gelen veriler doğrulanmalı
4. **Business Logic:** Fiyat hesaplamaları backend'de yapılmalı

**Güvenli Kod Örneği:**
```javascript
// Yanlış yaklaşım
app.post('/cart', (req, res) => {
    const price = req.body.price; // Kullanıcıdan alınan fiyat - TEHLİKELİ!
});

// Doğru yaklaşım  
app.post('/cart', (req, res) => {
    const productId = req.body.productId;
    const price = database.getProductPrice(productId); // DB'den alınan fiyat - GÜVENLİ
});
```

### Karmaşık Senaryolar
Bu zafiyet, çok adımlı süreçlerde daha da tehlikeli hale gelir:
- 1. adımda alınan form verisi 3. adımda da kullanılıyorsa
- Session'da saklanan veriler doğrulanmadan işleniyorsa
- Workflow süreçlerinde ara adımlarda manipülasyon mümkünse

## Lab 2: High-Level Logic Vulnerability

### Senaryo Açıklaması
Bu laboratuvarda negatif miktar (quantity) değerleri kullanarak fiyat manipülasyonu gerçekleştirilmektedir. Uygulama, negatif değerleri düzgün şekilde handle etmemektedir.

### Zafiyet Analizi

**Tespit Edilen Problemler:**
1. **Negatif Quantity Kabul Edilmesi:** -3 adet ürün eklenebiliyor
2. **Toplam Fiyat Kontrolü:** Toplam fiyat negatif olamaz kontrolü mevcut ancak yetersiz
3. **İş Mantığı Eksikliği:** Sepet işlemleri tutarsız davranışlar sergiliyor

### Saldırı Adımları

1. **Negatif Ürün Ekleme:**
   ```http
   POST /cart/add HTTP/1.1
   productId=expensive-jacket&quantity=-3
   ```

2. **Pozitif Ürün ile Dengeleme:**
   ```http  
   POST /cart/add HTTP/1.1
   productId=cheap-item&quantity=5
   ```

3. **Final Toplam Kontrolü:**
   - Pahalı ürün: -3 × $1337 = -$4011
   - Ucuz ürün: +5 × $10 = +$50
   - **Net Toplam:** -$3961 (Negatif toplam nedeniyle sipariş reddedilir)

![Negatif Quantity Örneği](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/5e73ed7b-2c51-4615-a42a-8108bcf12220)

### Çözüm Stratejisi

**Doğru Yaklaşım:**
1. Pahalı ürünü negatif miktarda ekle
2. Hesaplanan negatif tutarı pozitif hale getirecek kadar ucuz ürün ekle
3. Net tutarın pozitif ve bütçe içinde olmasını sağla

### Güvenlik Önlemleri

1. **Input Validation:**
   ```javascript
   function validateQuantity(quantity) {
       if (quantity <= 0) {
           throw new Error("Quantity must be positive");
       }
       return quantity;
   }
   ```

2. **Business Rules:**
   - Minimum quantity: 1
   - Maximum quantity per item: belirlenen limit
   - Total cart validation

## Lab 3: Low-Level Logic Flaw (Integer Overflow)

### Senaryo Açıklaması
Bu laboratuvarda integer overflow zafiyeti kullanılarak fiyat manipülasyonu gerçekleştirilmektedir. Çok sayıda ürün ekleyerek integer sınırları aşılmakta ve negatif değerler elde edilmektedir.

### Teknik Detaylar

**Integer Overflow Kavramı:**
- Integer data tipi belirli bit sınırlarına sahiptir (32-bit, 64-bit)
- Maximum değer aşıldığında overflow gerçekleşir
- Overflow sonucu değer negatif hale gelebilir

![Integer Overflow Request](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/84e6bd06-7a3d-45da-9349-c07e0c82900b)

### Saldırı Metodolojisi

1. **Maksimum Quantity Belirleme:**
   - Tek seferde maksimum kaç adet eklenebileceğini test et
   - Genellikle 99 veya 100 adet limit bulunur

2. **Otomatik İstek Gönderme:**
   ```http
   POST /cart/add HTTP/1.1
   productId=jacket&quantity=99
   ```
   Bu isteği sürekli tekrarla (F5 ile refresh)

3. **Overflow Tetikleme:**
   - 99 adet × çok sayıda istek = Integer overflow
   - Örnek: 99 × 50000 istek = Integer limitini aş

![Quantity Manipulation](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/46136a05-0e28-487c-ab95-c2f3c52e7dbd)

### Overflow Hesaplamaları

**32-bit Signed Integer:**
- Maximum değer: 2,147,483,647  
- Overflow sonrası: -2,147,483,648

**Pratik örnek:**
- Ürün fiyatı: $1337
- Hedef quantity: Integer overflow'a yol açacak miktar
- Hesaplama: (MAX_INT / price) + margin

![SQL Injection Risk](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/6af7fa94-f3ac-4fac-888b-c468e8679a28)

### İlave Güvenlik Riskleri

**SQL Injection Potansiyeli:**
Eğer quantity değeri direkt SQL sorgusunda kullanılıyorsa:
```sql
INSERT INTO cart_items (product_id, quantity) VALUES (1, [USER_INPUT])
```
Bu durumda SQL injection da mümkün hale gelir.

### Korunma Yöntemleri

1. **Data Type Kontrolü:**
   ```python
   MAX_QUANTITY = 1000
   
   def validate_quantity(quantity):
       if not isinstance(quantity, int):
           raise ValueError("Quantity must be integer")
       if quantity < 1 or quantity > MAX_QUANTITY:
           raise ValueError(f"Quantity must be between 1 and {MAX_QUANTITY}")
       return quantity
   ```

2. **Overflow Koruması:**
   ```java
   public boolean addToCart(int productId, int quantity) {
       long currentTotal = getCurrentCartTotal();
       long newTotal = Math.addExact(currentTotal, quantity); // ArithmeticException fırlatır
       
       if (newTotal > MAX_CART_TOTAL) {
           throw new BusinessLogicException("Cart total exceeded");
       }
       return true;
   }
   ```

3. **Database Constraints:**
   ```sql
   ALTER TABLE cart_items 
   ADD CONSTRAINT quantity_check 
   CHECK (quantity > 0 AND quantity <= 1000);
   ```

## Genel Güvenlik Önerileri

### 1. Defensive Programming
- Tüm kullanıcı inputlarını doğrulama
- Business rules'ı server-side'da uygulama
- Edge case'leri düşünme

### 2. Testing Stratejileri
- Boundary value testing
- Negative testing
- Stress testing
- Integer overflow testing

### 3. Monitoring ve Logging
- Anormal davranışları loglama
- Rate limiting uygulama
- Alert sistemleri kurma

### 4. Code Review
- Business logic kontrolü
- Input validation review
- Data type safety kontrolü

## Kaynaklar

- [OWASP Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
- [Web Security Academy Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
- [Integer Overflow and Underflow](https://cwe.mitre.org/data/definitions/190.html)