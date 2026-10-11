# Güvenlik Tarama Raporu — https://demo.example.com

> Bu, aracın çıktı biçimini gösteren **örnek/sahte** bir rapordur. Gerçek bir
> sistemi temsil etmez.

- **Tarih:** 2026-01-01 12:00 UTC
- **Modüller:** headers, cors, content, ports, tls, web
- **Özet:** 1 high, 2 medium, 3 low, 4 info

> ⚠️ Yalnızca yetkili olduğunuz sistemlerde kullanın. Bu rapor hassas bilgi içerebilir; herkese açık paylaşmayın.

## Bulgular

| Önem | Modül | Başlık |
|------|-------|--------|
| HIGH | content | Erişilebilir yol: /.git/config |
| MEDIUM | headers | Güvenlik başlığı eksik: Content-Security-Policy |
| MEDIUM | tls | TLS 1.0 destekleniyor (eski) |
| LOW | ports | Açık servis: 22/ssh |
| LOW | headers | Cookie bayrağı eksik |
| LOW | web | nuclei: ssh-sha1-hmac-algo |
| INFO | headers | Teknoloji ifşası: Server |
| INFO | cors | — |
| INFO | content | Erişilebilir yol: /api/health |
| INFO | ports | Açık portlar |

## Detaylar

### [HIGH] Erişilebilir yol: /.git/config
- **Modül:** content
- **Açıklama:** HTTP 200 döndü (catch-all 404 değil).
- **Kanıt:** `200 https://demo.example.com/.git/config`
- **Öneri:** Hassas dosya/dizinse erişimi kapat.

### [MEDIUM] Güvenlik başlığı eksik: Content-Security-Policy
- **Modül:** headers
- **Açıklama:** CSP yok: XSS etki alanı genişler
- **Kanıt:** `GET https://demo.example.com/ -> 200`
- **Öneri:** Content-Security-Policy yanıt başlığını ekle.

### [LOW] Açık servis: 22/ssh
- **Modül:** ports
- **Açıklama:** SSH internete açık — IP allowlist / VPN arkasına almayı değerlendir
- **Kanıt:** `22/tcp open ssh OpenSSH 8.9p1`

_(kısaltıldı)_
