# Changelog

Bu projenin tüm kayda değer değişiklikleri burada belgelenir.
Format [Keep a Changelog](https://keepachangelog.com/) tabanlı; sürümleme
[SemVer](https://semver.org/).

## [Unreleased]

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
