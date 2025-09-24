# Web Security Academy'de XSS Çözmeye Devam

## Giriş

Bu dokümanda Web Security Academy platform üzerinde Cross-Site Scripting (XSS) zafiyetlerini çözme sürecinde öğrenilen teknikler ve kavramlar ele alınmaktadır. XSS, web uygulamalarında kullanıcı inputlarının yetersiz filtrelenmesi sonucu ortaya çıkan ve saldırganlara kötü niyetli JavaScript kodları çalıştırma imkanı sunan kritik bir güvenlik zafiyetidir.

## Browser HTML Parsing Davranışı

Modern web tarayıcıları, eksik veya hatalı HTML yapılarını otomatik olarak düzeltmeye çalışır. Bu davranış, XSS saldırılarında önemli bir rol oynar.

### Otomatik HTML Yapısı Oluşturma

Tarayıcılar aşağıdaki kuralları takip eder:

1. **Eksik `<head>` ve `<body>` etiketleri**: Tarayıcı bu etiketleri eksik görürse otomatik olarak oluşturur
2. **Malformed etiketler**: Düzgün kapatılmamış etiketleri tarayıcı kendi mantığına göre kapatır
3. **Attribute düzeltmeleri**: Eksik tırnak işaretleri ve attribute'lar otomatik tamamlanır

### SVG ve XSS Payload Örneği

Aşağıdaki örnek, tarayıcının HTML parsing davranışını XSS için nasıl kullanabileceğimizi gösterir:

```html
<svg onload=alert(1) <="" html="">
```

**Tarayıcının işleme süreci:**

1. **İlk adım**: `<head>` ve `<body>` etiketlerini otomatik ekler
2. **İkinci adım**: `<svg>` etiketi görür ve `onload` attribute'unu tespit eder
3. **Üçüncü adım**: Eksik tırnak işaretlerini otomatik tamamlar
4. **Dördüncü adım**: Yeni satır karakterinden sonra `<` işareti görür ancak geçerli data bulamaz
5. **Beşinci adım**: `html=""` kısmını bir attribute olarak yorumlar ve ekler
6. **Altıncı adım**: Açık kalan tüm etiketleri (`<svg>`, `<body>`, `<html>`) sırasıyla kapatır

### Sonuç HTML Yapısı

Tarayıcı tarafından düzeltilen final HTML yapısı:

```html
<html>
<head></head>
<body>
    <svg onload="alert(1)" <="" html="">
    </svg>
</body>
</html>
```

Bu süreçte `onload` event'i tetiklenir ve JavaScript kodu çalışır.

## XSS Saldırı Vektörleri

### 1. DOM-based XSS
- Kullanıcı inputunun client-side JavaScript ile işlenmesi
- `innerHTML`, `document.write()` gibi tehlikeli fonksiyonlar

### 2. Reflected XSS  
- Kullanıcı inputunun HTTP response'da doğrudan yansıtılması
- URL parametreleri, form inputları

### 3. Stored XSS
- Kötü niyetli kodun veritabanında saklanması
- Yorum sistemleri, profil bilgileri

## Korunma Yöntemleri

1. **Input Validation**: Tüm kullanıcı inputlarını doğrulama
2. **Output Encoding**: HTML, JavaScript, CSS context'e göre encoding
3. **Content Security Policy (CSP)**: Güvenlik politikaları belirleme
4. **Secure Coding**: Güvenli kodlama pratiklerini uygulama

## Laboratuvar Sonuçları

![XSS Payload Örneği](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/21de8d5d-2b3e-4a5b-820b-eabd7a5fd38a)

*Yukarıdaki görsel, tarayıcının HTML parsing sürecini ve XSS payload'unun nasıl işlendiğini göstermektedir.*

## Kaynaklar

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Web Security Academy XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [HTML5 Security Cheatsheet](https://html5sec.org/)