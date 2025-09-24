# Information Disclosure (Bilgi İfşası) Zafiyetleri

## Giriş

Information Disclosure (Bilgi İfşası), web uygulamalarının hassas bilgileri yetkisiz kullanıcılara açığa çıkarması durumudur. Bu zafiyet türü, saldırganların sistem hakkında bilgi toplamalarına ve daha gelişmiş saldırılar gerçekleştirmelerine olanak sağlar.

## Bilgi İfşası Türleri

### 1. Error Message Disclosure
Hata mesajlarında sistem bilgilerinin açığa çıkması:

```python
# Yanlış yaklaşım
try:
    user = database.get_user(user_id)
except Exception as e:
    return f"Database error: {str(e)}"  # Stack trace ifşası!

# Doğru yaklaşım  
try:
    user = database.get_user(user_id)
except Exception as e:
    logger.error(f"Database error for user {user_id}: {str(e)}")
    return "An error occurred while processing your request"
```

### 2. Debug Information Leakage
Debug modunda çalışan uygulamalarda bilgi sızıntısı:

- Stack trace'ler
- Database bağlantı bilgileri
- Framework versiyonları
- Dosya yolları

### 3. Configuration Exposure
Yapılandırma dosyalarının açığa çıkması:

```bash
# Yaygın exposed dosyalar
/.env
/config.php
/web.config
/.git/config
/package.json
```

### 4. Source Code Disclosure
Kaynak kodunun ifşa edilmesi:

- Backup dosyaları (index.php~, index.php.bak)
- Version control dosyaları (.git, .svn)
- Temporary dosyalar

## Yaygın Information Disclosure Senaryoları

### SQL Error Messages

**Vulnerable Example:**
```php
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$result = mysql_query($query) or die(mysql_error());
```

**Error Output:**
```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1
```

Bu hata mesajı şunları ifşa eder:
- Database türü (MySQL)
- SQL syntax bilgisi
- Injection noktası

### File Path Disclosure

**Vulnerable Code:**
```php
include($_GET['page'] . '.php');
```

**Error Message:**
```
Warning: include(/var/www/html/../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/index.php on line 15
```

İfşa edilen bilgiler:
- Tam dosya yolu: `/var/www/html/`
- İşletim sistemi: Linux
- Web server konfigürasyonu

### HTTP Headers Information Disclosure

**Problematic Headers:**
```http
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: PHP/7.2.10
X-AspNet-Version: 4.0.30319
X-Debug-Token: sf-toolbar-block-123abc
```

### Username Enumeration

**Login Response Differences:**
```javascript
// Yanlış: Farklı error mesajları
if (!userExists(username)) {
    return "Username not found";
}
if (!validPassword(username, password)) {
    return "Invalid password";
}

// Doğru: Generic error message
if (!authenticate(username, password)) {
    return "Invalid username or password";
}
```

## Pratik Tespit Yöntemleri

### 1. Error-based Information Gathering

**SQL Injection Testing:**
```sql
' OR 1=1--
" OR 1=1--  
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**File Inclusion Testing:**
```
?page=../../../etc/passwd
?file=....//....//....//etc/passwd
?include=php://filter/read=convert.base64-encode/resource=index.php
```

### 2. Directory and File Enumeration

**Common Discovery Paths:**
```bash
# Administrative interfaces
/admin/
/administrator/
/wp-admin/
/phpmyadmin/

# Configuration files
/.env
/config.php
/.htaccess
/web.config

# Version control
/.git/
/.svn/
/.hg/

# Backup files
/backup/
/backups/
index.php.bak
config.php~
```

### 3. HTTP Methods Testing

```bash
# OPTIONS method
curl -X OPTIONS http://target.com/api/users

# TRACE method (XST)
curl -X TRACE http://target.com/ 

# HEAD method for info gathering
curl -I http://target.com/
```

## Korunma Yöntemleri

### 1. Error Handling

**Generic Error Messages:**
```python
class SecurityAwareException(Exception):
    def __init__(self, internal_message, user_message="An error occurred"):
        self.internal_message = internal_message
        self.user_message = user_message
        super().__init__(internal_message)

def safe_database_operation():
    try:
        # Database operation
        result = db.execute(query)
        return result
    except DatabaseException as e:
        logger.error(f"Database error: {e}")
        raise SecurityAwareException(str(e), "Database temporarily unavailable")
```

### 2. Header Security

**Security Headers:**
```apache
# Apache configuration
Header unset Server
Header unset X-Powered-By
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set Referrer-Policy strict-origin-when-cross-origin
```

**Nginx configuration:**
```nginx
server_tokens off;
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;
add_header X-XSS-Protection "1; mode=block";
```

### 3. File and Directory Protection

**.htaccess Protection:**
```apache
# Deny access to sensitive files
<Files ~ "^\.">
    Order allow,deny
    Deny from all
</Files>

# Block access to backup files
<FilesMatch "\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

**web.config Protection:**
```xml
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <hiddenSegments>
          <add segment="App_Data" />
          <add segment="bin" />
          <add segment="Config" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

### 4. Logging Best Practices

**Secure Logging:**
```python
import logging
from datetime import datetime

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/secure/logs/app.log'),
        logging.StreamHandler()
    ]
)

def secure_log_error(user_id, error_type, internal_details):
    # Log detailed info securely
    logging.error(f"User {user_id} - {error_type}: {internal_details}")
    
    # Return generic message
    return "An error occurred. Please contact support if the problem persists."
```

## Information Disclosure Automation Tools

### 1. Dirb/Dirbuster
```bash
dirb http://target.com/ /usr/share/dirb/wordlists/common.txt
```

### 2. Gobuster
```bash
gobuster dir -u http://target.com/ -w /usr/share/wordlists/dirb/common.txt
```

### 3. Custom Scripts
```python
import requests
import sys

def check_disclosure(url, paths):
    for path in paths:
        try:
            response = requests.get(f"{url}/{path}")
            if response.status_code == 200:
                print(f"[FOUND] {url}/{path}")
                if "mysql" in response.text.lower():
                    print("  -> Potential database info disclosure")
        except:
            continue

# Common disclosure paths
paths = ['.env', 'config.php', '.git/config', 'phpinfo.php']
check_disclosure('http://target.com', paths)
```

## Gerçek Dünya Örnekleri

### 1. GitHub Token Exposure

**Problem:**
```bash
# .env file accidentally committed
DB_PASSWORD=super_secret_pass
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
```

**Solution:**
```bash
# .gitignore
.env
.env.local
.env.production
config/secrets.yml
```

### 2. Stack Trace Information Disclosure

**Django Debug Mode:**
```python
# settings.py - PRODUCTION'da DEBUG=False olmalı
DEBUG = True  # Bu production'da False olmalı!
ALLOWED_HOSTS = []  # Production'da specific hosts
```

### 3. AWS S3 Bucket Enumeration

**Exposed Bucket:**
```bash
# Public bucket discovery
aws s3 ls s3://company-backups --no-sign-request

# Common bucket naming patterns
company-backups
company-logs  
company-prod-backup
```

## Monitoring ve Detection

### 1. Log Analysis

**Suspicious Patterns:**
```bash
# 40x responses in logs
grep "HTTP/1.1\" 40[0-9]" access.log | head -20

# Directory traversal attempts
grep "\.\." access.log | grep -E "(etc|passwd|shadow)"

# Information gathering attempts
grep -E "(phpinfo|test\.php|config\.php)" access.log
```

### 2. Automated Monitoring

**SIEM Rules:**
```yaml
# Example SIEM rule for information disclosure
rule:
  name: "Information Disclosure Attempt"
  condition: |
    (status_code >= 200 and status_code < 300) and
    (path contains ".env" or path contains "config.php" or 
     path contains ".git" or path contains "phpinfo")
  action: alert
  severity: medium
```

## Kaynaklar

- [OWASP Information Exposure](https://owasp.org/www-community/vulnerabilities/Information_exposure)
- [CWE-200: Information Exposure](https://cwe.mitre.org/data/definitions/200.html)
- [NIST SP 800-53 System and Information Integrity Controls](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls)

---

> **Not:** Bu doküman orijinal yayın kaynağının mevcut olmaması sebebiyle Information Disclosure konusunda kapsamlı bir referans oluşturmak amacıyla hazırlanmıştır. Pratik örnekler ve güncel güvenlik yaklaşımları ile desteklenmiştir.
