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
    },
}


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
