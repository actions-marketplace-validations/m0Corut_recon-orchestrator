# Changelog

Bu projenin tüm kayda değer değişiklikleri burada belgelenir.
Format [Keep a Changelog](https://keepachangelog.com/) tabanlı; sürümleme
[SemVer](https://semver.org/).

## [Unreleased]

### Added
- `crawl` modülü (katana): siteyi tarayıp endpoint/parametre haritası çıkarır
  (host-içi, GET, bağlı JS'i de ayrıştırır). Keşfedilen URL'ler bağlamda saklanır.
- `--dast` artık OpenAPI şeması yoksa da çalışır: siteyi crawl edip yalnızca
  parametre taşıyan host-içi GET URL'lerini nuclei DAST ile fuzz eder.
- `katana` araç olarak eklendi (Docker imajında da; `v1.8.0`).

### Changed
- nuclei şablonları kalıcı bir Docker volume'unda (`recon-nuclei-templates`)
  önbelleğe alınır; her taramada ~14.000 şablonun yeniden indirilmesi önlenir.

## [1.1.1] - 2026-10-12

### Fixed
- `recon doctor`: araç durum sütunu hizalı (uzun araç adları, ör. `subfinder`,
  satırı kaydırıyordu).

### Changed
- README kurulum bölümü 1.1.0'a göre güncellendi (PyPI önerilen yöntem, sabit
  imaj etiketi, araç sürümleri, 1.0'dan yükseltme notu); PyPI proje sayfası bu
  sürümle güncel README'yi gösterir.

## [1.1.0] - 2026-10-12

### Added
- Bastırma dosyası (`.reconignore.yml`, `--suppress-file`): gerekçe zorunlu,
  `expires` tarihi, rule_id glob, hedef ve fingerprint filtresi. Bastırılanlar
  sayımlara ve kapılara girmez, raporlarda ayrı listelenir.
- Alt alan adı keşfi (`--discover`, `discover` modülü): crt.sh → Cert Spotter
  yedekli sertifika şeffaflığı + varsa subfinder, canlı host yoklama, sahipsiz
  CNAME / subdomain takeover tespiti. Yeni alt alan adları baseline diff ile
  "yeni" bulgu olur. `--scan-discovered` ile keşfedilenler de taranır;
  üçüncü taraf CNAME'ler asla yoklanmaz.
- Uyarlanabilir hız sınırı: hedef 429/503 dönünce otomatik yavaşlama,
  `Retry-After` desteği, ardından kademeli hızlanma; rapora
  `meta.throttled_responses` yazılır.
- `--resume`: modül bazlı checkpoint ile yarıda kalan taramayı sürdürme.
- `--dast`: API şemasının yalnızca GET işlemlerini içeren ve sunucusu hedefe
  sabitlenmiş kopyası üzerinde nuclei DAST.
- Eklenti sistemi: `recon_orchestrator.modules` entry point grubu.
- `recon trend`: taramalar arası geçmişi gösteren tek dosyalık HTML.
- `subfinder` araç olarak eklendi (Docker imajında da var; `v2.17.0`).
- Webhook bildirimi (`--notify`, `--notify-env`, `--notify-min-severity`):
  yalnızca yeni bulgularda; Slack/Discord/Telegram/genel JSON. Kanıt gönderilmez.

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

[Unreleased]: https://github.com/m0Corut/recon-orchestrator/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/m0Corut/recon-orchestrator/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/m0Corut/recon-orchestrator/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/m0Corut/recon-orchestrator/releases/tag/v1.0.0
[0.2.0]: https://github.com/m0Corut/recon-orchestrator/releases/tag/v0.2.0
[0.1.0]: https://github.com/m0Corut/recon-orchestrator/releases/tag/v0.1.0
