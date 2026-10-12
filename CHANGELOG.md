# Changelog

Bu projenin tüm kayda değer değişiklikleri burada belgelenir.
Format [Keep a Changelog](https://keepachangelog.com/) tabanlı; sürümleme
[SemVer](https://semver.org/).

## [Unreleased]

### Security
- `authz`: kimlik başlığı yalnızca aynı origin'e (şema, host, port) gönderilir;
  başka bir kapsam içi host'a veya https→http yönlendirmede düşürülür
  (`scoped_get(auth_headers=...)`).
- Kapsam: `--allow-private` artık gerçekten uygulanıyor. Yalnızca wildcard ile
  eşleşen bir host özel/loopback/link-local adrese (ör. bulut metadata
  `169.254.169.254`) çözülüyorsa istek reddedilir. Tam adıyla verilen host'lar
  (ör. `http://localhost:8000`) etkilenmez.
- Araç imajları sabitlendi: `nuclei:v3.11.1`, `nmap:7.98`, `testssl.sh:3.2`
  (Dockerfile'da testssl `v3.2.4`).

### Fixed
- `authz`: getirilemeyen veya kapsam dışı sayfalar artık sessizce atlanmıyor;
  `authz.page-not-checked` bilgi bulgusu üretiliyor ve rapor "açık yok" demiyor.

## [1.0.0] - 2026-10-12

### Added
- Run-to-run diff + `--fail-on-new` (otomatik baseline, `recon diff`).
- YAML yapılandırma (`recon init`, `--config`), çoklu hedef.
- Paralel modül çalıştırma + ortak hız bütçesi (`--jobs`, `--serial`).
- Tek dosya HTML rapor + `--format` seçimi.
- DNS/e-posta modülü (SPF/DMARC/DKIM/CAA/MX).
- Yeniden kullanılabilir GitHub Action (`action.yml`).
- Araç çalıştırıcı soyutlaması (Docker/native, `--runner`).
- Orkestratör Docker imajı (araçlar paketli) + GHCR yayını.
- Authenticated (salt-okunur) erişim kontrolü modülü (`authz`).
- OpenAPI/Swagger şema-güdümlü endpoint kapsamı (`openapi`).
- Opsiyonel GitHub issue oluşturma.
- Opsiyonel analist özet katmanı (OpenAI-uyumlu + Anthropic).
- SMTP/mail güvenliği modülü (STARTTLS/MTA-STS/TLS-RPT).
- `recon modules`, `recon doctor`, `--quiet`; `docs/report.schema.json`.

## [0.2.0] - 2026-10-11

### Added
- Kararlı bulgu kimliği: her bulguda `rule_id` + `fingerprint`.
- Modül çıktı ayrıştırması saf fonksiyonlara çıkarıldı (Docker'sız test edilebilir).
- Motor/CLI ayrımı: `engine.run_scan`, tipli `ScanContext`, modül registry.
- GitHub Actions self-CI: ruff + mypy + pytest (Python 3.9–3.13).
- Yapısal araç çıktısı: nmap XML, nuclei JSONL (CVE/CVSS dahil), testssl JSON.
- İki dilli rapor: İngilizce varsayılan, `--lang tr` ile Türkçe.
- Kapsam (scope) güvenliği: allowlist + her-adım redirect kontrolü (`--scope`,
  `--allow-private`).
- SARIF sağlamlaştırma: kural yardımı (help/fullDescription/helpUri) ve
  invocation metadata (zaman, başarı durumu, hatalar).

### Fixed
- nmap `tcpwrapped`/doğrulanamayan servisler artık yanlışlıkla DB/servis açığı
  olarak yüksek önemle işaretlenmiyor.

## [0.1.0] - 2026-10-11

### Added
- İlk sürüm: 6 modül (headers, cors, content, ports, tls, web), Markdown/JSON/
  SARIF rapor, `--authorized` yetki kapısı, `--fail-on` CI çıkış kodu.

[Unreleased]: https://github.com/m0Corut/recon-orchestrator/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/m0Corut/recon-orchestrator/releases/tag/v0.2.0
[0.1.0]: https://github.com/m0Corut/recon-orchestrator/releases/tag/v0.1.0
