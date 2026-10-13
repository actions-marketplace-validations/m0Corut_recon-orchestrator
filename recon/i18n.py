"""Localization: catalogue of Turkish translations + report UI strings.

Modules author their findings in English (the canonical fallback). This module
maps a finding's ``msg_key`` to translated templates; ``localize()`` fills the
template with the finding's ``params``. English is the default; unknown keys or
languages fall back to the module-authored English text, so nothing is ever
blank. SARIF/JSON identity stays language-independent (rule_id/fingerprint).
"""
from __future__ import annotations

from typing import Any

LANGS = ("en", "tr")
DEFAULT_LANG = "en"

# msg_key -> {lang -> {title?, detail?, recommendation?}} with {param} placeholders.
# Only Turkish is listed; English comes from the module-authored text.
CATALOG: dict[str, dict[str, dict[str, str]]] = {
    # crawl / cms / idor
    # headers M1 — CSP/HSTS/cookie quality
    "headers.csp-unsafe-inline": {"tr": {"title": "CSP zayıflığı: unsafe-inline",
        "detail": "script-src nonce/hash olmadan 'unsafe-inline' izni veriyor."}},
    "headers.csp-unsafe-eval": {"tr": {"title": "CSP zayıflığı: unsafe-eval",
        "detail": "script-src 'unsafe-eval' izni veriyor."}},
    "headers.csp-wildcard-source": {"tr": {"title": "CSP zayıflığı: joker kaynak",
        "detail": "{token} geniş/joker bir kaynak içeriyor."}},
    "headers.csp-missing-object-src": {"tr": {"title": "CSP: object-src yok",
        "detail": "object-src yok ve default-src ile kısıtlanmamış."}},
    "headers.csp-missing-base-uri": {"tr": {"title": "CSP: base-uri yok",
        "detail": "base-uri direktifi yok."}},
    "headers.csp-nonce-without-strict-dynamic": {"tr": {
        "title": "CSP: nonce var, strict-dynamic yok",
        "detail": "Nonce/hash var ama 'strict-dynamic' yok (allow-list bypass sınıfı)."}},
    "headers.csp-report-only": {"tr": {"title": "CSP yalnızca Report-Only",
        "detail": "CSP yalnızca rapor modunda; uygulanmıyor."}},
    "headers.csp-unparseable": {"tr": {"title": "CSP ayrıştırılamadı",
        "detail": "CSP başlığı ayrıştırılamadı."}},
    "headers.hsts-short-max-age": {"tr": {"title": "HSTS max-age kısa",
        "detail": "max-age={max_age} (< 15552000, ~180g)."}},
    "headers.hsts-no-subdomains": {"tr": {"title": "HSTS includeSubDomains yok",
        "detail": "Alt alan adları HSTS kapsamında değil."}},
    "headers.hsts-over-http": {"tr": {"title": "HSTS HTTP üzerinden",
        "detail": "Düz-HTTP yanıtındaki HSTS tarayıcılarca yok sayılır."}},
    "headers.cookie-samesite-none-insecure": {"tr": {
        "title": "Çerez SameSite=None, Secure yok: {cookie}",
        "detail": "SameSite=None, Secure gerektirir; aksi halde reddedilir."}},
    "headers.cookie-session-over-http": {"tr": {
        "title": "Oturum çerezi HTTP üzerinden: {cookie}",
        "detail": "Oturum çerezi düz-HTTP yanıtında ayarlandı."}},
    "headers.cookie-broad-domain": {"tr": {
        "title": "Çerez geniş alana kapsamlı: {cookie}",
        "detail": "Domain={domain}, kardeş alt alan adlarını da kapsıyor."}},
    "headers.cookie-no-host-prefix": {"tr": {
        "title": "Oturum çerezinde __Host-/__Secure- öneki yok: {cookie}",
        "detail": "Önek, çerezi fiksasyon/üzerine yazmaya karşı sertleştirir."}},
    "content.exposed-panel": {"tr": {
        "title": "Açık panel/endpoint: /{path}",
        "detail": "HTTP {status} döndü (catch-all {base} değil)."}},
    "content.unverified-path": {"tr": {
        "title": "Yol 200 döndü (doğrulanmadı): /{path}",
        "detail": "HTTP 200 ama hassas-içerik imzası eşleşmedi (olası soft-404)."}},
    "hostinject.reflected-in-location": {"tr": {
        "title": "Sahte host Location başlığına yansıyor (sinyal, manuel doğrula)",
        "detail": "Sahte host Location başlığına yansıyor. İşlem öncesi manuel doğrula."}},
    "hostinject.reflected-in-resource-url": {"tr": {
        "title": "Sahte host kaynak/canonical URL'e yansıyor (sinyal, manuel doğrula)",
        "detail": "Sahte host bir kaynak/canonical URL'e yansıyor. Manuel doğrula."}},
    "hostinject.reflected-in-body": {"tr": {
        "title": "Sahte host yanıt gövdesine yansıyor (sinyal, manuel doğrula)",
        "detail": "Sahte host yanıt gövdesine yansıyor. Manuel doğrula."}},
    "hostinject.cacheable-response": {"tr": {
        "title": "Yansıtan yanıt önbelleğe alınabilir (sinyal, manuel doğrula)",
        "detail": "Yansıtan yanıt önbellek başlıkları taşıyor; paylaşımlı bir "
                  "önbellek zehirlenen içeriği sunabilir. Manuel doğrula."}},
    "hostinject.no-reflection": {"tr": {
        "title": "Host-header yansıması görülmedi",
        "detail": "Hedef, sahte bir host başlığını yansıtmadı."}},
    "hostinject.unreachable": {"tr": {
        "title": "Host-header kontrolü hedefi getiremedi",
        "detail": "Baseline isteği başarısız oldu."}},
    "passive.jwt-alg-none": {"tr": {"title": "JWT: alg=none",
        "detail": "JWT alg=none kullanıyor (imza doğrulanmıyor)."}},
    "passive.jwt-no-exp": {"tr": {"title": "JWT: exp yok",
        "detail": "JWT'de exp yok (süresi dolmuyor)."}},
    "passive.jwt-long-lived": {"tr": {"title": "JWT: uzun ömürlü",
        "detail": "JWT ömrü 30 günü aşıyor."}},
    "passive.jwt-sensitive-claims": {"tr": {"title": "JWT: hassas claim'ler",
        "detail": "JWT payload'ı kimlik/rol claim'leri taşıyor (herkesçe okunur)."}},
    "passive.jwt-in-url": {"tr": {"title": "JWT URL'de",
        "detail": "URL'de bir JWT görünüyor (log/referrer sızıntısı)."}},
    "passive.sri-missing": {"tr": {"title": "SRI olmayan üçüncü taraf kaynak: {src}",
        "detail": "Çapraz-kaynak script/stil integrity olmadan (tedarik zinciri riski)."}},
    "passive.cross-domain-script": {"tr": {"title": "Üçüncü taraf script host: {host}",
        "detail": "Script üçüncü taraf bir host'tan yükleniyor."}},
    "passive.private-ip-disclosure": {"tr": {"title": "İfşa: özel IP",
        "detail": "Yanıtta özel/iç IP adresi ifşa ediliyor."}},
    "passive.internal-hostname-disclosure": {"tr": {"title": "İfşa: iç hostname",
        "detail": "İç hostname (.local/.internal/.corp/.lan) ifşa ediliyor."}},
    "passive.absolute-path-disclosure": {"tr": {"title": "İfşa: sunucu dosya yolu",
        "detail": "Sunucu dosya sistemi yolu ifşa ediliyor."}},
    "passive.stack-trace": {"tr": {"title": "İfşa: stack trace",
        "detail": "Bir framework stack trace / hata ayıklama hatası ifşa ediliyor."}},
    "passive.mixed-content-active": {"tr": {"title": "Aktif karışık içerik",
        "detail": "https sayfada http:// script yükleniyor (MITM/enjeksiyon)."}},
    "passive.mixed-content-passive": {"tr": {"title": "Pasif karışık içerik",
        "detail": "https sayfada http:// stil dosyası yükleniyor."}},
    "passive.session-id-in-url": {"tr": {"title": "URL'de oturum kimliği: {param}",
        "detail": "Oturum/token kimliği URL'de taşınıyor (log/referrer/geçmiş sızıntısı)."}},
    "passive.html-comment-sensitive": {"tr": {"title": "İfşa: hassas HTML yorumu",
        "detail": "HTML yorumu hassas anahtar kelimeler içeriyor (todo/fixme/password/debug)."}},
    "passive.robots-missing": {"tr": {"title": "robots.txt yok",
        "detail": "Sunucu robots.txt sunmuyor."}},
    "passive.robots-reveals-paths": {"tr": {"title": "robots.txt hassas yolları açığa çıkarıyor",
        "detail": "robots.txt Disallow kayıtları hassas yolları işaret ediyor (getirilmedi)."}},
    "passive.security-txt-missing": {"tr": {"title": "security.txt yok",
        "detail": "/.well-known/security.txt yok (RFC 9116)."}},
    "passive.security-txt-no-contact": {"tr": {"title": "security.txt Contact alanı yok",
        "detail": "security.txt mevcut ama Contact alanı yok."}},
    "passive.security-txt-expired": {"tr": {"title": "security.txt süresi dolmuş",
        "detail": "security.txt Expires alanı geçmiş bir tarihte."}},
    "passive.clean": {"tr": {"title": "pasif: kayda değer bir şey yok",
        "detail": "Getirilen sayfalarda pasif bir sorun bulunamadı."}},
    "graphql.introspection-enabled": {"tr": {
        "title": "GraphQL introspection açık: {url}",
        "detail": "Introspection tüm şemayı döndürüyor; production'da kapat."}},
    "graphql.endpoint-found": {"tr": {
        "title": "GraphQL endpoint bulundu: {url}",
        "detail": "Bir GraphQL endpoint'i yanıt veriyor (introspection kapalı görünüyor)."}},
    "graphql.debug-errors": {"tr": {
        "title": "GraphQL ayrıntılı hatalar: {url}",
        "detail": "Hata yanıtı yığın izi / exception detayı içeriyor (debug modu).",
        "recommendation": "Production'da ayrıntılı hata çıktısını kapat."}},
    "graphql.ide-exposed": {"tr": {
        "title": "GraphQL IDE açık: {url}",
        "detail": "GraphiQL/Playground IDE sunuluyor; şema keşfini kolaylaştırır.",
        "recommendation": "GraphQL IDE'yi production'da açığa çıkarma."}},
    "graphql.get-query-allowed": {"tr": {
        "title": "GraphQL sorguları GET ile kabul ediliyor: {url}",
        "detail": "GET sorguları CSRF ile tetiklenebilir ve önbelleğe alınabilir.",
        "recommendation": "GraphQL'i yalnızca POST üzerinden kabul et."}},
    "graphql.none-found": {"tr": {
        "title": "GraphQL endpoint bulunamadı",
        "detail": "Yaygın yollarda yanıt veren bir GraphQL endpoint'i yok."}},
    "redirect.open-redirect": {"tr": {
        "title": "Açık yönlendirme: {url}",
        "detail": "Yönlendirme parametresi kullanıcıyı saldırganın seçtiği host'a "
                  "gönderiyor.",
        "recommendation": "Yönlendirme hedeflerini bir allow-list ile doğrula."}},
    "redirect.reflected-not-redirected": {"tr": {
        "title": "Yönlendirme parametresi yansıtıldı (yönlendirme yok): {url}",
        "detail": "Canary değeri sayfada yansıtılıyor ama yönlendirme olmadı; "
                  "manuel kontrol önerilir."}},
    "redirect.clean": {"tr": {
        "title": "Açık yönlendirme bulunamadı",
        "detail": "{tested} yönlendirme-tipi parametre denendi; hiçbiri site dışına "
                  "yönlendirmedi."}},
    "redirect.no-candidates": {"tr": {
        "title": "Yönlendirme-tipi parametre bulunamadı",
        "detail": "Hiçbir crawl URL'inde yönlendirme-tipi parametre yok (bulmak için "
                  "crawl modülüyle çalıştır)."}},
    "jsrecon.secret": {"tr": {
        "title": "JavaScript'te olası {family}",
        "detail": "İstemci tarafı JS içinde {family} biçiminde bir sır gömülü."}},
    "jsrecon.vulnerable-library": {"tr": {
        "title": "Güncel olmayan JS kütüphanesi: {lib} {version}",
        "detail": "{lib} {version} < {fixed}; bilinen açıklar içerir."}},
    "jsrecon.sourcemap-exposed": {"tr": {
        "title": "JavaScript source map ifşa",
        "detail": ".js.map erişilebilir; küçültülmemiş özgün kaynağı açığa çıkarır."}},
    "jsrecon.firebase-config": {"tr": {
        "title": "JavaScript'te Firebase web yapılandırması",
        "detail": "Firebase istemci yapılandırması mevcut. Bu genelde herkese "
                  "açıktır; Firebase güvenlik kurallarının gizliliğe dayanmadığını "
                  "doğrulayın."}},
    "jsrecon.no-scripts": {"tr": {
        "title": "Aynı kaynaklı JavaScript bulunamadı",
        "detail": "İncelenecek bir şey yok (aynı host'ta <script src> ya da .js URL yok)."}},
    "jsrecon.library-inventory": {"tr": {
        "title": "JavaScript kütüphane envanteri",
        "detail": "Tespit edilen kütüphaneler listelendi."}},
    "csrf.form-without-token": {"tr": {
        "title": "CSRF token'ı olmayan durum değiştiren form",
        "detail": "POST/PUT/PATCH/DELETE formunda anti-CSRF token'ı ve SameSite "
                  "oturum çerezi yok; cross-site sahte istekle tetiklenebilir."}},
    "csrf.form-without-token-samesite-only": {"tr": {
        "title": "CSRF token'ı yok (yalnızca SameSite koruması)",
        "detail": "Anti-CSRF token'ı yok ama SameSite oturum çerezi kısmi koruma "
                  "sağlıyor. Derinlemesine savunma için token ekle."}},
    "csrf.login-form-without-token": {"tr": {
        "title": "CSRF token'ı olmayan giriş formu",
        "detail": "Giriş formunda anti-CSRF token'ı yok (login-CSRF riski)."}},
    "csrf.no-forms-found": {"tr": {
        "title": "HTML form bulunamadı",
        "detail": "Değerlendirilecek HTML form yok (JSON API / SPA fetch ile "
                  "gönderir; bu pasif kontrol bunu kapsamaz)."}},
    "crawl.surface": {"tr": {
        "title": "Saldırı yüzeyi: {host} üzerinde {urls} endpoint",
        "detail": "Crawl {urls} host-içi URL buldu, {params} tanesi sorgu "
                  "parametreli (fuzz edilebilir). Parametrelileri fuzz etmek için "
                  "--dast ile çalıştır."}},
    "cms.detected": {"tr": {
        "title": "CMS tespit edildi: {cms}",
        "detail": "{cms} tespit edildi (sürüm {version}). CMS ve eklentilerini "
                  "güncel tut; sürümü gizle."}},
    "idor.possible": {"tr": {
        "title": "Olası IDOR: {location}",
        "detail": "Komşu bir nesne id'si 200 ile farklı bir nesne döndürdü; nesne "
                  "düzeyinde yetkilendirme eksik olabilir. Bu nesnenin bu kullanıcı "
                  "tarafından erişilebilir olması gerekip gerekmediğini manuel "
                  "doğrula."}},
    # discover
    "discover.host": {"tr": {
        "title": "Canlı host: {host}",
        "detail": "{url} HTTP {status} yanıtı veriyor."}},
    "discover.takeover": {"tr": {
        "title": "Olası subdomain takeover: {host}",
        "detail": "{host}, çözülmeyen {target} adresine CNAME. Bu sağlayıcıda "
                  "adı genelde herkes alabilir; saldırgan alt alan adında içerik "
                  "yayınlayabilir.",
        "recommendation": "DNS kaydını sil ya da işaret ettiği kaynağı geri al."}},
    "discover.dangling-cname": {"tr": {
        "title": "Sahipsiz CNAME: {host}",
        "detail": "{host}, çözülmeyen {target} adresine CNAME. Bu ad başkası "
                  "tarafından alınabilirse alt alan adını o kontrol eder.",
        "recommendation": "DNS kaydını sil ya da işaret ettiği kaynağı geri al."}},
    "discover.summary": {"tr": {
        "title": "{domain} için keşif özeti",
        "detail": "{sources} kaynağından {domain} altında {resolved} ad çözüldü; "
                  "{live} canlı web host'u, {third} üçüncü taraf (yoklanmadı), "
                  "{private} özel adres (atlandı)."}},
    "web.dast-ran": {"tr": {
        "title": "API şeması üzerinde DAST çalıştı",
        "detail": "nuclei DAST şablonları {spec} şemasındaki {ops} GET işlemine "
                  "karşı çalıştırıldı."}},
    "authz.page-not-checked": {"tr": {
        "title": "Sayfa kontrol edilemedi: {page}",
        "detail": "Sayfa getirilemediği için erişim kontrolü doğrulanmadı: {reason}.",
        "recommendation": "Yolu ve hedefin erişilebilir olduğunu kontrol edip "
                          "yeniden çalıştır."}},
    # headers
    "headers.missing-hsts": {"tr": {
        "title": "Güvenlik başlığı eksik: Strict-Transport-Security",
        "detail": "HSTS yok: protokol düşürme / MITM riski.",
        "recommendation": "Strict-Transport-Security yanıt başlığını ekle."}},
    "headers.missing-csp": {"tr": {
        "title": "Güvenlik başlığı eksik: Content-Security-Policy",
        "detail": "CSP yok: XSS etki alanı genişler.",
        "recommendation": "Content-Security-Policy ekle."}},
    "headers.missing-nosniff": {"tr": {
        "title": "Güvenlik başlığı eksik: X-Content-Type-Options",
        "detail": "nosniff yok: MIME sniffing riski.",
        "recommendation": "X-Content-Type-Options: nosniff ekle."}},
    "headers.missing-xfo": {"tr": {
        "title": "Güvenlik başlığı eksik: X-Frame-Options",
        "detail": "yok: clickjacking riski (CSP frame-ancestors yoksa).",
        "recommendation": "X-Frame-Options veya CSP frame-ancestors ekle."}},
    "headers.missing-referrer-policy": {"tr": {
        "title": "Güvenlik başlığı eksik: Referrer-Policy",
        "detail": "yok: referrer üzerinden bilgi sızıntısı.",
        "recommendation": "Referrer-Policy ekle."}},
    "headers.missing-permissions-policy": {"tr": {
        "title": "Güvenlik başlığı eksik: Permissions-Policy",
        "detail": "yok: tarayıcı özellikleri kısıtlanmamış.",
        "recommendation": "Permissions-Policy ekle."}},
    "headers.tech-disclosure": {"tr": {
        "title": "Teknoloji ifşası: {header}",
        "detail": "{header}: {value}",
        "recommendation": "{header} başlığını kaldır/genelleştir."}},
    "headers.cookie-flags": {"tr": {
        "title": "Cookie bayrağı eksik",
        "detail": "Eksik: {missing}",
        "recommendation": "Session cookie'lerine Secure + HttpOnly + SameSite ekle."}},
    "headers.request-failed": {"tr": {
        "title": "HTTP isteği başarısız", "detail": "{target} alınamadı: {error}"}},
    # cors
    "cors.reflects-origin-with-credentials": {"tr": {
        "title": "CORS yanlış yapılandırması",
        "detail": "Sunucu '{origin}' Origin'ini credentials ile yansıtıyor.",
        "recommendation": "Origin'leri allowlist ile sınırla; '*'+credentials kullanma."}},
    "cors.permissive-acao": {"tr": {
        "title": "CORS yanlış yapılandırması",
        "detail": "Sunucu '{origin}' Origin'ini yansıtıyor (ACAO={acao}).",
        "recommendation": "İzin verilen origin'leri allowlist ile sınırla."}},
    # content
    "content.sensitive-file": {"tr": {
        "title": "Erişilebilir hassas dosya: /{path}",
        "detail": "HTTP {status} döndü (catch-all {base} değil).",
        "recommendation": "Bu dosyaya erişimi kapat."}},
    "content.accessible-path": {"tr": {
        "title": "Erişilebilir yol: /{path}",
        "detail": "HTTP {status} döndü (catch-all {base} değil).",
        "recommendation": "Hassas dizinse erişimi kapat."}},
    "content.clean": {"tr": {
        "title": "İçerik keşfi: temiz",
        "detail": "{count} yol denendi, kayda değer yol yok (catch-all: {base})."}},
    # ports
    "ports.exposed": {"tr": {
        "title": "Açık servis: {port}/{service}",
        "detail": "Bu servis internetten erişilebilir.",
        "recommendation": "Erişimi kısıtla (VPN/allowlist/firewall) ya da iç ağa bağla."}},
    "ports.open-unconfirmed": {"tr": {
        "title": "Açık port (servis doğrulanamadı): {port}/{proto}",
        "detail": "{port} yanıt veriyor ama servis doğrulanamadı (nmap: {service}). "
                  "Güvenlik duvarı tüm portlara yanıt veriyor olabilir."}},
    "ports.open-ports": {"tr": {
        "title": "Açık portlar", "detail": "Tespit edilen açık portlar."}},
    "ports.image-unavailable": {"tr": {"title": "nmap imajı indirilemedi"}},
    # tls
    "tls.config-ok": {"tr": {
        "title": "TLS yapılandırması sağlam",
        "detail": "testssl kayda değer (LOW+) bir sorun bildirmedi."}},
    "tls.image-unavailable": {"tr": {"title": "testssl imajı indirilemedi"}},
    "tls.no-output": {"tr": {
        "title": "TLS: JSON çıktısı alınamadı",
        "detail": "testssl JSON dosyası oluşmadı."}},
    # web
    "web.nuclei.no-match": {"tr": {
        "title": "nuclei: eşleşme yok", "detail": "{severities} seviyesinde bulgu yok."}},
    "web.profile-ran": {"tr": {
        "title": "nuclei profili '{profile}' çalıştı",
        "detail": "Ek nuclei etiket seti tarandı (profil: {profile})."}},
    "web.image-unavailable": {"tr": {"title": "nuclei imajı indirilemedi"}},
}

# Report chrome (headings, labels) per language.
UI: dict[str, dict[str, str]] = {
    "en": {
        "report_title": "Security Scan Report",
        "date": "Date", "modules": "Modules", "summary": "Summary",
        "no_findings": "no findings",
        "warning": "⚠️ Use only on systems you are authorized to test. This report "
                   "may contain sensitive data; do not share it publicly.",
        "findings": "Findings", "details": "Details",
        "severity": "Severity", "module": "Module", "title_col": "Title",
        "evidence": "Evidence", "recommendation": "Recommendation",
        "detail": "Detail", "errors": "Errors",
        "baseline": "Baseline comparison", "new": "new", "resolved": "resolved",
        "new_findings": "New since baseline",
        "analyst": "Analyst summary (automated, unverified)",
        # CLI chrome
        "banner_warning": "WARNING: this tool sends real requests to the "
            "target. Use it only on systems you OWN or have WRITTEN "
            "AUTHORIZATION to test. Unauthorized scanning is a crime in most "
            "jurisdictions. You are fully responsible.",
        "err": "ERROR", "err_need_authorized": "--authorized flag is required. "
            "The scan will not start without confirming you are authorized.",
        "err_no_target": "no target given (positional argument or config targets).",
        "err_unknown_modules": "unknown module(s)",
        "err_unknown_formats": "unknown format(s)",
        "err_config": "config",
        "running": "running...", "skipped": "skipped.",
        "resumed": "reused from the interrupted run.",
        "scan_done": "Done. Report:", "no_findings_short": "no findings",
        "baseline_line": "baseline: {new} new, {resolved} resolved",
        "available_modules": "Available modules:",
        "docker_tool": "docker/tool", "pure_python": "pure-python",
        "active": "active", "passive": "passive",
        "doctor_title": "recon doctor",
        "docker_label": "Docker", "native_tools_label": "Native tools:",
        "optional_packages_label": "Optional packages:",
        "present": "present", "missing": "MISSING",
        "wrote_template": "Wrote example config:",
        "analyst_generating": "Generating analyst summary",
        "analyst_skipped_no_key": "missing; analyst summary skipped.",
        "analyst_error": "Analyst error:",
        "github_result": "GitHub: {created} issue(s) opened, {closed} closed.",
        "github_error": "GitHub issue error:",
        "github_skipped_no_token": "GITHUB_TOKEN missing; issue creation skipped.",
        "suppressed": "Suppressed (accepted risks)", "reason": "Reason",
        "suppressed_line": "{n} finding(s) suppressed",
        "suppress_expired": "suppression for {rule} expired on {date}; "
            "it no longer applies",
        "err_suppress": "suppression file",
        "notify_sent": "notification sent to {n} webhook(s)",
        "notify_error": "Notification error:",
        "throttled": "target throttled {n} request(s) (429/503); the scan slowed "
            "down automatically, results may be incomplete",
        "discovered_scanning": "scanning {n} discovered host(s)",
        "discovered_hint": "{n} live subdomain(s) found; add --scan-discovered "
            "to scan them (only if you are authorized for each)",
    },
    "tr": {
        "report_title": "Güvenlik Tarama Raporu",
        "date": "Tarih", "modules": "Modüller", "summary": "Özet",
        "no_findings": "bulgu yok",
        "warning": "⚠️ Yalnızca yetkili olduğunuz sistemlerde kullanın. Bu rapor "
                   "hassas bilgi içerebilir; herkese açık paylaşmayın.",
        "findings": "Bulgular", "details": "Detaylar",
        "severity": "Önem", "module": "Modül", "title_col": "Başlık",
        "evidence": "Kanıt", "recommendation": "Öneri",
        "detail": "Açıklama", "errors": "Hatalar",
        "baseline": "Önceki tarama ile karşılaştırma", "new": "yeni",
        "resolved": "çözülen", "new_findings": "Önceki taramaya göre yeni",
        "analyst": "Analist özeti (otomatik, doğrulanmamış)",
        # CLI chrome
        "banner_warning": "UYARI: Bu araç hedefe gerçek istekler gönderir. "
            "Yalnızca SAHİBİ OLDUĞUNUZ veya YAZILI İZNİNİZ olan sistemlerde "
            "kullanın. Yetkisiz tarama çoğu ülkede suçtur. Sorumluluk tamamen "
            "size aittir.",
        "err": "HATA", "err_need_authorized": "--authorized bayrağı gerekli. "
            "Yetkiniz olduğunu onaylamadan tarama başlatılmaz.",
        "err_no_target": "hedef verilmedi (pozisyonel argüman ya da config targets).",
        "err_unknown_modules": "bilinmeyen modül(ler)",
        "err_unknown_formats": "bilinmeyen biçim(ler)",
        "err_config": "config",
        "running": "çalışıyor...", "skipped": "atlandı.",
        "resumed": "yarıda kalan taramadan alındı.",
        "scan_done": "Bitti. Rapor:", "no_findings_short": "bulgu yok",
        "baseline_line": "baseline: {new} yeni, {resolved} çözülen",
        "available_modules": "Mevcut modüller:",
        "docker_tool": "docker/araç", "pure_python": "saf-python",
        "active": "aktif", "passive": "pasif",
        "doctor_title": "recon doctor",
        "docker_label": "Docker", "native_tools_label": "Native araçlar:",
        "optional_packages_label": "Opsiyonel paketler:",
        "present": "var", "missing": "YOK",
        "wrote_template": "Örnek yapılandırma yazıldı:",
        "analyst_generating": "Analist özeti üretiliyor",
        "analyst_skipped_no_key": "yok; analist özeti atlandı.",
        "analyst_error": "Analist hatası:",
        "github_result": "GitHub: {created} issue açıldı, {closed} kapatıldı.",
        "github_error": "GitHub issue hatası:",
        "github_skipped_no_token": "GITHUB_TOKEN yok; issue oluşturma atlandı.",
        "suppressed": "Bastırılanlar (kabul edilen riskler)", "reason": "Gerekçe",
        "suppressed_line": "{n} bulgu bastırıldı",
        "suppress_expired": "{rule} için bastırmanın süresi {date} tarihinde "
            "doldu; artık uygulanmıyor",
        "err_suppress": "bastırma dosyası",
        "notify_sent": "{n} webhook'a bildirim gönderildi",
        "notify_error": "Bildirim hatası:",
        "throttled": "hedef {n} isteği kısıtladı (429/503); tarama otomatik "
            "yavaşladı, sonuçlar eksik olabilir",
        "discovered_scanning": "keşfedilen {n} host taranıyor",
        "discovered_hint": "{n} canlı alt alan adı bulundu; taramak için "
            "--scan-discovered ekle (yalnızca her biri için yetkin varsa)",
    },
}


# `recon modules` descriptions in Turkish, keyed by module name. English comes
# from each ModuleSpec.description in recon/modules/__init__.py.
MODULE_DESC_TR: dict[str, str] = {
    "headers": "Güvenlik başlıkları, cookie bayrakları ve teknoloji ifşası",
    "cors": "CORS yanlış yapılandırması (Origin yansıması)",
    "content": "Dizin/dosya keşfi (catch-all filtreli)",
    "ports": "Açık port/servis taraması (nmap)",
    "tls": "TLS yapılandırması: eski protokol/zayıf şifreleyici (testssl)",
    "web": "Topluluk şablonlarıyla açık/teknoloji tespiti (nuclei)",
    "dns": "DNS & e-posta güvenliği: SPF/DMARC/DKIM/CAA/MX (dnspython gerekir)",
    "authz": "Giriş sonrası (salt-okunur) erişim kontrolü — kimlik bilgisi gerekir",
    "openapi": "OpenAPI/Swagger şema-güdümlü endpoint kapsamı (salt-okunur)",
    "mail": "SMTP/mail: STARTTLS, MTA-STS, TLS-RPT (kapsam korumalı, salt-okunur)",
    "discover": "Alt alan adı envanteri (CT kayıtları + varsa subfinder), canlı "
                "host yoklama, sahipsiz CNAME / takeover kontrolü",
    "crawl": "Endpoint/parametre haritası için siteyi tarar (katana)",
    "csrf": "HTML formlarında CSRF koruması kontrolü (pasif, salt-okunur)",
    "jsrecon": "İstemci JS: sızan sırlar, eski kütüphaneler, açık source map'ler",
    "graphql": "GraphQL ifşası: introspection, IDE, hata ayıklama (salt-okunur)",
    "redirect": "Yönlendirme parametrelerinde açık yönlendirme tespiti (salt-okunur)",
    "passive": "Pasif ekstralar: JWT/SRI/URL'de session/ifşa/robots/security.txt",
    "hostinject": "Host-header injection / cache poisoning sinyalleri "
                  "(salt-okunur, manuel doğrula)",
    "cms": "CMS tespiti + WordPress ifşa kontrolleri (salt-okunur)",
    "idor": "IDOR / nesne düzeyi yetki kontrolü taraması (salt-okunur, opt-in)",
}


def module_description(name: str, english: str, lang: str) -> str:
    if lang == "tr":
        return MODULE_DESC_TR.get(name, english)
    return english


def ui(lang: str) -> dict[str, str]:
    return UI.get(lang, UI[DEFAULT_LANG])


def localize(finding: Any, lang: str) -> tuple[str, str, str]:
    """Return (title, detail, recommendation) for a finding in `lang`.

    Falls back to the finding's English-authored text for unknown keys/langs or
    when a template references a missing param.
    """
    entry = CATALOG.get(finding.msg_key, {}).get(lang)
    if not entry:
        return finding.title, finding.detail, finding.recommendation
    params = finding.params or {}

    def fmt(tmpl: str | None, fallback: str) -> str:
        if not tmpl:
            return fallback
        try:
            return tmpl.format(**params)
        except (KeyError, IndexError, ValueError):
            return fallback

    return (
        fmt(entry.get("title"), finding.title),
        fmt(entry.get("detail"), finding.detail),
        fmt(entry.get("recommendation"), finding.recommendation),
    )
