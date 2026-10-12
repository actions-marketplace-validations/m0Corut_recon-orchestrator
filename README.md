# recon-orchestrator

[![ci](https://github.com/m0Corut/recon-orchestrator/actions/workflows/ci.yml/badge.svg)](https://github.com/m0Corut/recon-orchestrator/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.9%2B-blue)

**[English](#english)** | **[Türkçe](#türkçe)**

---

## English

A lightweight **tool orchestrator** for authorized security testing. One
command runs well-known open-source security tools (nmap, nuclei, testssl.sh)
plus built-in Python checks (security headers, CORS, content discovery, DNS/
email security, authenticated access control, OpenAPI coverage, mail/SMTP)
against a target, merges the results, and produces **Markdown + JSON + SARIF +
HTML** reports.

> No dependency on an expensive LLM — works entirely with free tools. An
> optional "analyst" summarization layer exists but is strictly opt-in.

### ⚠️ Legal notice

This tool sends **real requests** to the target. Use it only on systems you
**own** or have **written authorization** to test. Unauthorized scanning is a
crime in most jurisdictions; responsibility is entirely yours. The tool
requires the `--authorized` flag before it will run.

### Requirements

- Python 3.9+
- `requests`, `pyyaml` (installed automatically)
- Optional `[dns]` extra (`pip install ".[dns]"`) for the `dns` and `mail` modules
- Docker — only needed for the `ports`, `tls`, `web` modules (images are pulled
  automatically on first run). Without Docker those modules are skipped; the
  pure-Python modules still run. Or use `--runner native` / the bundled
  [Docker image](#docker-image-tools-included) which ships the tools as native
  binaries.

### Sample output

![recon-orchestrator demo](docs/demo.svg)

See [examples/sample-report.md](examples/sample-report.md) for the report format.

### Install

```bash
git clone https://github.com/m0Corut/recon-orchestrator
cd recon-orchestrator
pip install -r requirements.txt
# or as a package (with the DNS/mail extra):
pip install ".[dns]"
```

### Docker image (tools included)

A single image bundling nmap, nuclei and testssl.sh as native binaries — no
local install needed:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/m0corut/recon-orchestrator \
  https://example.com --authorized
```

### Usage

```bash
# All modules (including Docker-based ones)
python -m recon https://example.com --authorized

# Fast, Docker-free checks only
python -m recon example.com -m headers,cors,content,dns --authorized

# Lower the rate (be gentle on production), use your own wordlist
python -m recon https://example.com --authorized --rate 10 --wordlist paths.txt

# CI: exit code 2 if any finding is high+
python -m recon https://example.com --authorized --fail-on high

# Report language (default English; Turkish available):
python -m recon https://example.com --authorized --lang tr

# Scope: only the target host by default; allow extra hosts:
python -m recon https://example.com --authorized --scope "api.example.com,*.cdn.example.com"

# CI: fail only on a NEW finding (the previous run is the baseline automatically):
python -m recon https://example.com --authorized --fail-on-new high

# Compare two reports directly:
python -m recon diff ./previous/report.json ./latest/report.json

# YAML config: generate a template, edit it, run it:
python -m recon init
python -m recon --config recon.yaml --authorized

# Pick report formats, concurrency, and the tool runner:
python -m recon https://example.com --authorized --format html,json --jobs 3 --runner native

# Authenticated (read-only) access-control check:
python -m recon https://example.com --authorized -m authz \
  --auth-header-env SESSION_COOKIE --auth-page /account --auth-page /admin

# OpenAPI/Swagger-driven endpoint coverage:
python -m recon https://api.example.com --authorized -m openapi --spec ./openapi.json

# Optional: open a GitHub issue per new finding, and an optional LLM summary:
python -m recon https://example.com --authorized --fail-on-new high \
  --github-issues myorg/myrepo --analyst anthropic
```

**Parallelism:** modules run in parallel by default (the slowest tools —
nuclei/testssl/nmap — now overlap). Use `--jobs N` to cap concurrency or
`--serial` to force sequential execution. Active HTTP modules share one
aggregate rate budget (`--rate`, total requests/sec), so parallelism never
increases load on the target.

**Config file:** `recon init` writes a `recon.yaml` where you define targets,
scope, modules, language, `fail_on`/`fail_on_new`, and per-module options
(nuclei tags, port count, wordlist, etc.). CLI flags override the config file.
`targets` can list multiple hosts — each is scanned in turn.

**Run diff:** every run automatically uses the most recent previous run for the
same host as a baseline and reports new/resolved findings (disable with
`--no-auto-baseline`). `--fail-on-new <severity>` only fails the build when a
**new** finding reaches that severity — so CI doesn't stay red forever on a
pre-existing issue.

**Scope safety:** by default the tool only ever requests the target host.
HTTP modules check every request *and* every redirect against the scope
allowlist, so a redirect probe cannot bounce onto a third-party host.
`--allow-private` is required for internal/loopback addresses.

**Tool runner:** `--runner auto|docker|native` controls how external tools
run. `auto` prefers natively installed binaries and falls back to Docker.

Reports default to English; `--lang tr` produces Turkish. The `rule_id` and
SARIF identity are language-independent — only human-readable text is
translated.

Each run writes `report.md`, `report.json`, `findings.sarif`, `report.html`
under `recon_runs/<host>_<timestamp>/`.

### Modules

| Module | Docker? | What it does |
|--------|---------|---------------|
| `headers` | No | Security headers + cookie flags + tech disclosure |
| `cors` | No | Reflected-Origin CORS misconfiguration |
| `content` | No | Path/file discovery (catch-all filtered) |
| `dns` | No (needs `[dns]`) | SPF / DMARC / DKIM / CAA / MX email security |
| `ports` | Yes (nmap) | Open ports/services + risky-service warnings |
| `tls` | Yes (testssl) | Old protocols / weak ciphers |
| `web` | Yes (nuclei) | Known-issue/tech detection via community templates |
| `authz` | No | Authenticated, read-only access-control checks (opt-in, needs credentials) |
| `openapi` | No | OpenAPI/Swagger-driven endpoint coverage (read-only) |
| `mail` | No (needs `[dns]`) | SMTP STARTTLS / MTA-STS / TLS-RPT (scope-respecting) |

### Architecture

```
recon/
├── cli.py            # argparse + config merge + report writing
├── engine.py          # run_scan(): module scheduling, parallelism, dedup
├── context.py         # ScanContext (typed options shared with modules)
├── scope.py            # allowlist + scoped_get() (redirect-safe HTTP)
├── ratelimit.py        # shared aggregate rate limiter
├── runner.py           # DockerRunner / NativeRunner abstraction
├── diff.py             # fingerprint-based run-to-run diff
├── config.py           # YAML config loading/validation
├── findings.py         # Finding / ScanResult, rule_id + fingerprint
├── i18n.py             # EN/TR message catalogue
├── report.py / report_html.py   # Markdown / JSON / SARIF / HTML renderers
├── analyst/            # optional LLM summarization (opt-in, no SDKs)
├── integrations/github.py       # optional GitHub issue creation
└── modules/            # each exposes NAME, NEEDS_DOCKER, run(target, ctx)
```

Adding a module: create `recon/modules/<name>.py` with `NAME`,
`NEEDS_DOCKER`, and `run(target, ctx) -> list[Finding]`; register it in
`recon/modules/__init__.py`; author English text with a stable `rule_id` and
add Turkish translations to `recon/i18n.py`; extract tool-output parsing into a
pure function and add fixture-based tests.

### CI (GitHub Actions)

Reusable **composite action** for a one-step scan + SARIF upload:

```yaml
- uses: m0Corut/recon-orchestrator@main
  with:
    target: https://staging.example.com
    modules: "headers,cors,content,dns"
    fail-on-new: "high"
    lang: "en"
```

`.github/workflows/scan.yml` is a weekly-scheduled + manually triggerable
example workflow using this action.

### Helper commands

```bash
python -m recon modules      # list modules and descriptions
python -m recon doctor       # check Docker/native tools and optional packages
python -m recon init         # write a recon.yaml template
python -m recon diff a.json b.json   # compare two reports
```

### Stability / versioning

From version 1.0, CLI flags and the `report.json` schema
([docs/report.schema.json](docs/report.schema.json)) are stable; breaking
changes ship with a new major version and are noted in the CHANGELOG.

### Development

```bash
pip install -e ".[dev]"
ruff check recon/ tests/
mypy recon/
pytest -q
pre-commit install   # optional
```

Every push/PR runs lint + mypy + pytest on Python 3.9–3.13 via `ci.yml`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for details.

### License

Apache-2.0 — see [LICENSE](LICENSE).

### Acknowledgements

[nmap](https://nmap.org), [nuclei](https://github.com/projectdiscovery/nuclei),
[testssl.sh](https://github.com/drwetter/testssl.sh). This project orchestrates
these tools; it does not replace them.

---

## Türkçe

Yetkili güvenlik testleri için hafif bir **araç orkestratörü**. Tek bir komutla
tanınmış açık kaynak güvenlik araçlarını (nmap, nuclei, testssl.sh) ve yerleşik
Python kontrollerini (güvenlik başlıkları, CORS, içerik keşfi, DNS/e-posta
güvenliği, giriş sonrası erişim kontrolü, OpenAPI kapsamı, mail/SMTP) bir
hedefe karşı çalıştırır; sonuçları tek biçimde toplayıp **Markdown + JSON +
SARIF + HTML** rapor üretir.

> Pahalı bir LLM'e bağımlılığı **yoktur**; tamamen ücretsiz araçlarla çalışır.
> İsteğe bağlı bir "analist" özet katmanı vardır, kesinlikle opt-in'dir.

### ⚠️ Yasal uyarı

Bu araç hedefe **gerçek istekler gönderir**. Yalnızca **sahibi olduğunuz** veya
**yazılı izniniz olan** sistemlerde kullanın. Yetkisiz tarama çoğu ülkede suçtur.
Sorumluluk tamamen size aittir. Araç, bunu onaylamanız için `--authorized`
bayrağını zorunlu kılar.

### Gereksinimler

- Python 3.9+
- `requests`, `pyyaml` (otomatik kurulur)
- `dns` ve `mail` modülleri için opsiyonel `[dns]` extra (`pip install ".[dns]"`)
- Docker — yalnızca `ports`, `tls`, `web` modülleri için (imajlar ilk
  çalıştırmada otomatik çekilir). Docker yoksa bu modüller atlanır, Python
  tabanlı modüller yine çalışır. Alternatif: `--runner native` veya araçları
  native binary olarak içeren [Docker imajı](#docker-imajı-araçlar-dahil).

### Örnek çıktı

![recon-orchestrator demo](docs/demo.svg)

Rapor biçimi için bkz. [examples/sample-report.md](examples/sample-report.md).

### Kurulum

```bash
git clone https://github.com/m0Corut/recon-orchestrator
cd recon-orchestrator
pip install -r requirements.txt
# veya paket olarak (DNS/mail extra'sıyla):
pip install ".[dns]"
```

### Docker imajı (araçlar dahil)

nmap, nuclei ve testssl.sh'ı native binary olarak içeren tek imaj — yerel
kuruluma gerek yok:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/m0corut/recon-orchestrator \
  https://ornek.com --authorized
```

### Kullanım

```bash
# Tüm modüller (Docker gerektirenler dahil)
python -m recon https://ornek.com --authorized

# Sadece Docker'sız hızlı kontroller
python -m recon ornek.com -m headers,cors,content,dns --authorized

# Rate limit düşür (production'da nazik ol), kendi wordlist'in
python -m recon https://ornek.com --authorized --rate 10 --wordlist paths.txt

# CI için: high+ bulgu varsa çıkış kodu 2
python -m recon https://ornek.com --authorized --fail-on high

# Rapor dili (varsayılan İngilizce; Türkçe için):
python -m recon https://ornek.com --authorized --lang tr

# Kapsam: varsayılan sadece hedef host; ek host'lara izin ver:
python -m recon https://ornek.com --authorized --scope "api.ornek.com,*.cdn.ornek.com"

# CI'da sadece YENİ bulguda patlat (önceki çalıştırma otomatik baz alınır):
python -m recon https://ornek.com --authorized --fail-on-new high

# İki raporu doğrudan karşılaştır:
python -m recon diff ./onceki/report.json ./yeni/report.json

# YAML yapılandırma: örnek oluştur, düzenle, çalıştır:
python -m recon init
python -m recon --config recon.yaml --authorized

# Rapor biçimi, eşzamanlılık ve araç çalıştırıcı seçimi:
python -m recon https://ornek.com --authorized --format html,json --jobs 3 --runner native

# Giriş sonrası (salt-okunur) erişim kontrolü:
python -m recon https://ornek.com --authorized -m authz \
  --auth-header-env SESSION_COOKIE --auth-page /account --auth-page /admin

# OpenAPI/Swagger şema-güdümlü endpoint kapsamı:
python -m recon https://api.ornek.com --authorized -m openapi --spec ./openapi.json

# Opsiyonel: yeni bulguda GitHub issue aç, LLM özeti al:
python -m recon https://ornek.com --authorized --fail-on-new high \
  --github-issues benim/reponum --analyst anthropic
```

**Paralellik:** Modüller varsayılan olarak paralel çalışır (en uzun süreyi alan
nuclei/testssl/nmap artık örtüşür). `--jobs N` ile eşzamanlılık sınırlanır,
`--serial` ile sıraya alınır. Aktif HTTP modülleri ortak bir hız bütçesini
(`--rate`, toplam istek/sn) paylaşır, böylece paralellik hedefi yormaz.

**Yapılandırma dosyası:** `recon init` ile oluşturduğun `recon.yaml`'da hedefler,
kapsam, modüller, dil, `fail_on`/`fail_on_new` ve modül ayarları (nuclei etiketleri,
port sayısı, wordlist vb.) tanımlanır. CLI bayrakları config'i ezer. `targets` birden
çok hedef içerebilir — hepsi sırayla taranır.

**Run diff:** Her çalıştırma, aynı host için en son önceki çalıştırmayı otomatik
baz alır ve yeni/çözülen bulguları raporlar (`--no-auto-baseline` ile kapatılır).
`--fail-on-new <önem>` yalnızca **yeni** bulgu bu seviyedeyse çıkış kodu 2 verir —
böylece CI, önceden var olan bir eksikte sürekli kırmızı olmaz.

**Kapsam güvenliği:** Araç varsayılan olarak yalnızca hedef host'a istek atar.
HTTP modülleri her isteği ve her yönlendirmeyi kapsam allowlist'ine karşı
kontrol eder, böylece bir yönlendirme probe'u 3. taraf bir host'a sıçrayamaz.
İç/özel adresler için `--allow-private` gerekir.

**Araç çalıştırıcı:** `--runner auto|docker|native`, dış araçların nasıl
çalışacağını seçer. `auto`, native kurulu binary'leri önceler, yoksa Docker'a
düşer.

Raporlar varsayılan olarak İngilizce üretilir; `--lang tr` ile Türkçe alınır.
Bulgu kimliği (`rule_id`) ve SARIF dilden bağımsızdır, sadece insan-okur metin
çevrilir.

Her çalıştırma `recon_runs/<host>_<zaman>/` altına `report.md`, `report.json`,
`findings.sarif`, `report.html` yazar.

### Modüller

| Modül | Docker? | Ne yapar |
|-------|---------|----------|
| `headers` | Hayır | Güvenlik başlıkları + cookie bayrakları + teknoloji ifşası |
| `cors` | Hayır | Kötü Origin yansıması (CORS yanlış yapılandırması) |
| `content` | Hayır | Dizin/dosya keşfi (catch-all filtreli) |
| `dns` | Hayır (`[dns]` gerekir) | SPF / DMARC / DKIM / CAA / MX e-posta güvenliği |
| `ports` | Evet (nmap) | Açık port/servis + riskli servis uyarıları |
| `tls` | Evet (testssl) | Eski protokol / zayıf şifreleyici |
| `web` | Evet (nuclei) | Topluluk şablonlarıyla açık/teknoloji tespiti |
| `authz` | Hayır | Giriş sonrası, salt-okunur erişim kontrolü (opt-in, kimlik bilgisi gerekir) |
| `openapi` | Hayır | OpenAPI/Swagger şema-güdümlü endpoint kapsamı (salt-okunur) |
| `mail` | Hayır (`[dns]` gerekir) | SMTP STARTTLS / MTA-STS / TLS-RPT (kapsam korumalı) |

### Mimari

```
recon/
├── cli.py            # argparse + config birleştirme + rapor yazımı
├── engine.py          # run_scan(): modül zamanlama, paralellik, dedup
├── context.py         # ScanContext (modüllerle paylaşılan tipli ayarlar)
├── scope.py            # allowlist + scoped_get() (redirect-güvenli HTTP)
├── ratelimit.py        # ortak toplam hız sınırlayıcı
├── runner.py           # DockerRunner / NativeRunner soyutlaması
├── diff.py             # fingerprint tabanlı run-to-run diff
├── config.py           # YAML config yükleme/doğrulama
├── findings.py         # Finding / ScanResult, rule_id + fingerprint
├── i18n.py             # EN/TR mesaj kataloğu
├── report.py / report_html.py   # Markdown / JSON / SARIF / HTML üreticiler
├── analyst/            # opsiyonel LLM özeti (opt-in, SDK'sız)
├── integrations/github.py       # opsiyonel GitHub issue oluşturma
└── modules/            # her biri NAME, NEEDS_DOCKER, run(target, ctx) verir
```

Yeni modül eklemek: `recon/modules/<ad>.py` oluştur (`NAME`, `NEEDS_DOCKER`,
`run(target, ctx) -> list[Finding]`), `recon/modules/__init__.py`'ye kaydet,
metni İngilizce yaz ve kararlı bir `rule_id` ver, Türkçe çevirisini
`recon/i18n.py`'ye ekle; araç çıktısı ayrıştırmasını saf fonksiyona çıkar ve
fixture tabanlı test ekle.

### CI (GitHub Actions)

Yeniden kullanılabilir **composite action** ile tek adımda tarama + SARIF upload:

```yaml
- uses: m0Corut/recon-orchestrator@main
  with:
    target: https://staging.ornek.com
    modules: "headers,cors,content,dns"
    fail-on-new: "high"
    lang: "en"
```

`.github/workflows/scan.yml` haftalık zamanlı + elle tetiklenebilir örnek bir
workflow'dur (bu action'ı kullanır).

### Yardımcı komutlar

```bash
python -m recon modules      # modülleri ve açıklamalarını listeler
python -m recon doctor       # Docker/native araç ve opsiyonel paket kontrolü
python -m recon init         # örnek recon.yaml yazar
python -m recon diff a.json b.json   # iki raporu karşılaştırır
```

### Kararlılık / sürümleme

Sürüm 1.0'dan itibaren CLI bayrakları ve `report.json` şeması
([docs/report.schema.json](docs/report.schema.json)) kararlıdır; kırıcı
değişiklikler yeni bir ana sürümle gelir ve CHANGELOG'da belirtilir.

### Geliştirme

```bash
pip install -e ".[dev]"
ruff check recon/ tests/
mypy recon/
pytest -q
pre-commit install   # opsiyonel
```

Her push/PR `ci.yml` ile lint + mypy + pytest'i (Python 3.9–3.13) çalıştırır.
Ayrıntılar için [CONTRIBUTING.md](CONTRIBUTING.md).

### Lisans

Apache-2.0 — bkz. [LICENSE](LICENSE).

### Teşekkür

[nmap](https://nmap.org), [nuclei](https://github.com/projectdiscovery/nuclei),
[testssl.sh](https://github.com/drwetter/testssl.sh) ekiplerine. Bu proje bu
araçları yönetir, yerlerine geçmez.
