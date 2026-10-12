# recon-orchestrator

[![ci](https://github.com/m0Corut/recon-orchestrator/actions/workflows/ci.yml/badge.svg)](https://github.com/m0Corut/recon-orchestrator/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.9%2B-blue)

**[English](#english)** | **[Türkçe](#türkçe)**

---

## English

### What is this?

`recon-orchestrator` is a command-line tool that checks a website, API, or
domain for common, well-known security misconfigurations — the kind of issues
that show up in almost every real-world penetration test: missing security
headers, exposed databases, outdated TLS, weak SPF/DMARC email records, leaky
API endpoints, pages that should require login but don't, and more.

It does **not** reinvent scanning from scratch. Instead it **orchestrates**
battle-tested, industry-standard open-source tools — [nmap](https://nmap.org)
(port scanning), [nuclei](https://github.com/projectdiscovery/nuclei)
(vulnerability templates), [testssl.sh](https://github.com/drwetter/testssl.sh)
(TLS auditing) — plus its own lightweight Python checks, runs them all against
one target, merges every result into one consistent format, and hands you a
single report instead of six different tool outputs to cross-reference by
hand.

**Who it's for:** developers and small teams who want a free, repeatable
security check of their own site before shipping, in CI, or on a schedule —
without paying for a commercial scanning platform or learning six separate
tools.

### Why use it instead of running the tools yourself?

You *could* run nmap, nuclei, and testssl.sh by hand — many people do. This
tool exists because that gets tedious fast:

- **One command, one report.** Instead of six terminal windows and six output
  formats, you get one Markdown/HTML report (for humans) and one JSON/SARIF
  report (for machines and CI).
- **Noise reduction.** Raw tool output is full of false-positive-prone,
  terminology-heavy lines. This project turns each one into a plain-language
  finding with a severity and a recommendation.
- **CI-friendly out of the box.** `--fail-on-new high` fails your build only
  when a *new* high-severity issue appears, not every time because of an
  old, already-known, accepted issue — so it's realistic to run on every pull
  request without constant red builds.
- **No vendor lock-in, no subscription, no LLM cost.** Everything here runs
  with free, open tools. An optional AI "executive summary" exists, but it is
  off by default and the tool is fully useful without it.

### How it works

When you run `recon <target> --authorized`, four things happen in order:

1. **Scope is locked.** The tool resolves your target's hostname and builds an
   allow-list (by default: just that one host). Every HTTP request any module
   makes — including following a redirect — is checked against this list
   first. This exists so that a redirect on the target site can never make the
   tool silently start probing some unrelated third-party domain.

2. **Modules run, in parallel, under a shared speed limit.** Each check
   (`headers`, `ports`, `tls`, …) is an independent Python module. They run
   concurrently so the slow ones (nmap, nuclei, testssl — these can take
   minutes) overlap instead of stacking up, which roughly halves total scan
   time. All modules that send real HTTP traffic share one request-rate budget
   (`--rate`, requests/second) so running things in parallel never increases
   load on the target beyond what you set.

3. **Results are merged and de-duplicated.** Every single finding gets a
   stable identifier (`rule_id`) and a fingerprint, independent of wording or
   language. If two modules happen to report the same underlying issue, it's
   only counted once. This same fingerprint is what makes run-to-run diffing
   possible (see below).

4. **Reports are written.** Four files land in `recon_runs/<host>_<timestamp>/`:
   a Markdown report to read, a JSON report for scripting, a SARIF file for
   GitHub's "Code scanning" UI, and a self-contained HTML page you can open in
   a browser or attach to an email — with no external resources loaded (your
   scan results never leave your machine unless you choose to send them
   somewhere).

On every subsequent scan of the *same* host, the tool automatically looks at
your last run and tells you what's **new** versus what you already knew
about — so a CI pipeline using `--fail-on-new` only turns red when something
actually changed for the worse.

### Installation

You need **Python 3.9 or newer**. Everything else is optional depending on
which modules you want:

| You want... | You need |
|---|---|
| The core checks (headers, CORS, content discovery) | Just Python + pip |
| DNS/email security (`dns`) and mail (`mail`) checks | the `[dns]` extra |
| Port scanning, TLS audit, nuclei templates (`ports`/`tls`/`web`) | Docker **or** the tools installed natively |

**Option A — clone and install (recommended for first try):**

```bash
git clone https://github.com/m0Corut/recon-orchestrator
cd recon-orchestrator
pip install ".[dns]"          # omit [dns] if you don't need the dns/mail modules
```

This installs a `recon` command on your PATH.

**Option B — install from PyPI (no cloning needed):**

```bash
pip install "recon-orchestrator[dns]"
```

**Option C — Docker image (zero local setup, tools included):**

If you don't want to install Python packages or Docker-pull individual tool
images, use the all-in-one image. It bundles nmap, nuclei, and testssl.sh as
native binaries inside the container, so it needs *only* Docker itself:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/m0corut/recon-orchestrator \
  https://example.com --authorized
```

**Checking your setup:** after installing, run `recon doctor` — it tells you
exactly which tools and optional packages it can see, so you know in advance
which modules will actually run.

### Your first scan, step by step

```bash
recon https://example.com --authorized
```

- `https://example.com` — **your own site**, or one you have written
  permission to test. The tool refuses to run without...
- `--authorized` — ...this flag, which is your explicit confirmation that you
  are allowed to test this target. There is no way around this check; it is
  intentional friction.

What you'll see: a progress line per module as it starts, then a summary line
like `3 info, 2 low, 1 medium` and the path to your report folder. Open
`recon_runs/example.com_<timestamp>/report.html` in a browser — it has a
severity breakdown at the top, a filterable findings table, and a plain-English
explanation and fix recommendation under each one.

If Docker isn't running or isn't installed, you'll see `[~] ports: skipped`
for the Docker-based modules — the scan still completes with whatever modules
could run, it never hard-fails just because one tool is missing.

**A gentler first run** — only the checks that need nothing but Python, which
is a good way to try the tool with zero setup:

```bash
recon example.com -m headers,cors,content,dns --authorized
```

### Using it continuously (CI)

The real value shows up when you run this regularly instead of once. Two
pieces make that practical:

```bash
# Only fail the build when something NEW and at least "high" severity appears.
# The previous run for the same host is used as the baseline automatically.
recon https://example.com --authorized --fail-on-new high
```

Or drop in the reusable GitHub Action:

```yaml
- uses: m0Corut/recon-orchestrator@main
  with:
    target: https://staging.example.com
    modules: "headers,cors,content,dns"
    fail-on-new: "high"
```

`.github/workflows/scan.yml` in this repo is a working example (weekly
schedule + manual trigger) you can copy into your own project.

**Accepted risks.** Some findings are known and deliberately accepted. List
them in `.reconignore.yml` (picked up automatically, or pass
`--suppress-file`). Each entry needs a reason; an optional `expires` date
makes the finding come back, and fail CI again, once the review date passes.
Suppressed findings are left out of counts and `--fail-on*` gates but still
listed in every report under "Suppressed".

```yaml
- rule_id: headers.missing-csp        # glob allowed: "headers.*"
  reason: "CSP rollout tracked in JIRA-123"
  expires: 2027-01-31
- rule_id: ports.notable
  reason: "Redis is firewalled to the VPN"
  fingerprint: 3f2a9c...              # optional: just this one instance
```

**Notifications.** A scheduled scan is only useful if someone sees it.
`--notify-env RECON_WEBHOOK` reads one or more webhook URLs (comma-separated)
from an environment variable and posts a short message only when there are
NEW findings at `--notify-min-severity` (default `medium`) or above. Slack,
Discord and Telegram (`https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>`)
URLs are detected automatically; anything else receives a generic JSON
payload. Messages contain titles and rule ids, never evidence.

### What each module actually checks

| Module | Needs | What it looks for |
|--------|-------|---------------------|
| `headers` | nothing | Missing security headers (HSTS, CSP, X-Frame-Options, …), insecure cookie flags, and server/framework version leaks |
| `cors` | nothing | A CORS policy that reflects an attacker-controlled Origin back, especially combined with credentials |
| `content` | nothing | Accidentally exposed files and paths (`.env`, `.git/config`, backup dumps, debug endpoints) |
| `dns` | `[dns]` extra | Missing or weak SPF/DMARC (email spoofing protection), missing DKIM, missing CAA |
| `ports` | Docker or nmap | Which ports are open and whether a risky service (database, Redis, RDP, …) is reachable from the internet |
| `tls` | Docker or testssl.sh | Outdated TLS versions and weak cipher suites |
| `web` | Docker or nuclei | Thousands of community-maintained signatures for known CVEs, exposed panels, and misconfigurations |
| `authz` | a session cookie/token you provide | Whether pages that should require login are actually reachable without one (read-only — GET/HEAD only, never submits forms) |
| `openapi` | an OpenAPI/Swagger spec | Whether endpoints the spec marks as requiring authentication are reachable without it |
| `mail` | `[dns]` extra | Whether your mail server offers STARTTLS, and whether MTA-STS/TLS-RPT are configured |

Run `recon modules` any time to see this list with each module's current
description.

### Useful flags at a glance

```bash
--lang tr                     # Turkish report text (default: English)
--format html,json            # choose which report files to write
--scope "api.x.com,*.cdn.x.com"  # allow extra hosts beyond the target itself
--rate 10                     # be gentler on a production target
--jobs 2 / --serial           # limit or disable module parallelism
--config recon.yaml           # load targets/options from a YAML file (recon init to generate one)
--runner native|docker|auto   # how external tools are executed
--analyst anthropic           # optional AI executive summary (opt-in, needs an API key)
--github-issues org/repo      # optional: file a GitHub issue per new finding
```

Full detail on every flag: `recon --help`.

### Architecture (for contributors)

```
recon/
├── cli.py              # argument parsing, config merging, writing reports
├── engine.py           # schedules modules, runs them in parallel, de-duplicates
├── context.py          # ScanContext: typed options shared with every module
├── scope.py            # the allow-list + the redirect-safe HTTP helper
├── ratelimit.py         # the shared, aggregate rate limiter
├── runner.py            # abstracts "run this external tool" over Docker or native binaries
├── diff.py              # fingerprint-based comparison between two runs
├── config.py            # YAML config file loading/validation
├── findings.py          # the Finding/ScanResult data model (rule_id, fingerprint, severity)
├── i18n.py              # English text + Turkish translation catalogue
├── report.py / report_html.py   # Markdown / JSON / SARIF / HTML renderers
├── analyst/             # optional LLM summarization (opt-in, plain HTTP, no SDKs)
├── integrations/github.py       # optional GitHub issue creation
└── modules/             # one file per check; each exposes NAME, NEEDS_DOCKER, run()
```

To add a module: create `recon/modules/<name>.py` exposing `NAME`,
`NEEDS_DOCKER`, and `run(target, ctx) -> list[Finding]`; register it in
`recon/modules/__init__.py`; write finding text in English with a stable
`rule_id`, add the Turkish translation to `recon/i18n.py`; keep any
tool-output parsing in a separate pure function so it's testable without
Docker or the network; add tests under `tests/`.

### Stability, development, license

CLI flags and the `report.json` schema
([docs/report.schema.json](docs/report.schema.json)) are stable from v1.0
onward; breaking changes get a new major version and a CHANGELOG entry.

```bash
pip install -e ".[dev]"
ruff check recon/ tests/ && mypy recon/ && pytest -q
```

Every push/PR runs this same check on Python 3.9–3.13. See
[CONTRIBUTING.md](CONTRIBUTING.md) to add a module or fix a bug.

Licensed under Apache-2.0 — see [LICENSE](LICENSE). Built on top of
[nmap](https://nmap.org), [nuclei](https://github.com/projectdiscovery/nuclei)
and [testssl.sh](https://github.com/drwetter/testssl.sh); this project
orchestrates these tools, it does not replace them.

### ⚠️ Legal

This tool sends real network requests to whatever target you give it. Only
use it against systems you **own** or have **written authorization** to test.
Unauthorized scanning is illegal in most jurisdictions — responsibility is
entirely yours. The `--authorized` flag exists specifically so you cannot run
a scan by accident without consciously confirming this.

---

## Türkçe

### Bu proje ne işe yarıyor?

`recon-orchestrator`, bir web sitesini, API'yi veya alan adını yaygın ve
bilinen güvenlik yanlış yapılandırmalarına karşı kontrol eden bir komut satırı
aracıdır — gerçek sızma testlerinin neredeyse hepsinde çıkan türden sorunlar:
eksik güvenlik başlıkları, internete açık veritabanları, güncel olmayan TLS,
zayıf SPF/DMARC e-posta kayıtları, bilgi sızdıran API endpoint'leri, giriş
gerektirmesi gerekirken gerektirmeyen sayfalar ve benzerleri.

Taramayı sıfırdan **yeniden icat etmez.** Onun yerine, sektörde kanıtlanmış
açık kaynak araçları — [nmap](https://nmap.org) (port taraması),
[nuclei](https://github.com/projectdiscovery/nuclei) (zafiyet şablonları),
[testssl.sh](https://github.com/drwetter/testssl.sh) (TLS denetimi) — ve
kendi hafif Python kontrollerini **orkestre eder**, hepsini tek bir hedefe
karşı çalıştırır, tüm sonuçları tek, tutarlı bir biçimde birleştirir ve sana
elle karşılaştırman gereken altı farklı araç çıktısı yerine tek bir rapor
verir.

**Kimler için:** kendi sitelerini yayına almadan önce, CI'da veya düzenli
aralıklarla ücretsiz ve tekrarlanabilir bir güvenlik kontrolü isteyen
geliştiriciler ve küçük ekipler — ticari bir tarama platformuna para
ödemeden ya da altı ayrı aracı öğrenmeden.

### Araçları kendim çalıştırmak yerine neden bunu kullanayım?

nmap, nuclei ve testssl.sh'ı elle de çalıştırabilirsin — çoğu kişi öyle yapıyor.
Bu proje, o işin hızla sıkıcı hale gelmesi yüzünden var:

- **Tek komut, tek rapor.** Altı terminal penceresi ve altı farklı çıktı
  biçimi yerine, insan için tek bir Markdown/HTML raporu ve makine/CI için
  tek bir JSON/SARIF raporu alırsın.
- **Gürültü azaltma.** Ham araç çıktısı, yanlış-pozitife meyilli ve jargon
  dolu satırlarla doludur. Bu proje her birini önem seviyesi ve öneri içeren
  sade bir bulguya çevirir.
- **Kutudan çıktığı gibi CI uyumlu.** `--fail-on-new high`, build'i yalnızca
  **yeni** bir yüksek önem seviyeli sorun çıktığında durdurur — eski, bilinen,
  kabul edilmiş bir sorun yüzünden her seferinde değil. Bu sayede her pull
  request'te çalıştırmak, sürekli kırmızı build'e boğulmadan gerçekçi olur.
- **Tedarikçi bağımlılığı yok, abonelik yok, LLM maliyeti yok.** Buradaki her
  şey ücretsiz, açık araçlarla çalışır. Opsiyonel bir AI "yönetici özeti"
  vardır ama varsayılan olarak kapalıdır ve araç onsuz da tam olarak
  kullanılabilir.

### Nasıl çalışır?

`recon <hedef> --authorized` çalıştırdığında, sırayla dört şey olur:

1. **Kapsam kilitlenir.** Araç, hedefinin host adını çözer ve bir izin
   listesi (allow-list) kurar (varsayılan: sadece o tek host). Herhangi bir
   modülün yaptığı her HTTP isteği — bir yönlendirmeyi takip etmek dahil —
   önce bu listeye karşı kontrol edilir. Bunun amacı, hedef sitedeki bir
   yönlendirmenin aracı sessizce ilgisiz bir üçüncü taraf alan adını
   yoklamaya başlatmasını kesinlikle engellemektir.

2. **Modüller paralel ve ortak bir hız sınırı altında çalışır.** Her kontrol
   (`headers`, `ports`, `tls`, …) bağımsız bir Python modülüdür. Eşzamanlı
   çalışırlar, böylece yavaş olanlar (nmap, nuclei, testssl — dakikalar
   sürebilir) üst üste binmek yerine örtüşür, bu da toplam tarama süresini
   kabaca yarıya indirir. Gerçek HTTP trafiği gönderen tüm modüller tek bir
   istek-hızı bütçesini (`--rate`, istek/saniye) paylaşır, böylece paralel
   çalışma hedefe binen yükü senin belirlediğinin üzerine çıkarmaz.

3. **Sonuçlar birleştirilir ve tekilleştirilir.** Her bulgu, kelime seçiminden
   veya dilden bağımsız kararlı bir kimlik (`rule_id`) ve bir parmak izi alır.
   İki modül aynı temel sorunu bildirirse, yalnızca bir kez sayılır. Bu aynı
   parmak izi, taramadan taramaya karşılaştırmayı (aşağıda) mümkün kılan şeydir.

4. **Raporlar yazılır.** `recon_runs/<host>_<zaman>/` altına dört dosya
   düşer: okumak için bir Markdown raporu, scriptleme için bir JSON raporu,
   GitHub'ın "Code scanning" arayüzü için bir SARIF dosyası, ve tarayıcıda
   açabileceğin veya e-postaya ekleyebileceğin, dışarıya hiçbir kaynak
   yüklemeyen (tarama sonuçların, sen göndermeyi seçmedikçe makinenden
   çıkmaz) bağımsız bir HTML sayfası.

Aynı host'u sonraki her taramada, araç otomatik olarak son çalıştırmana bakar
ve sana neyin **yeni** olduğunu, neyi zaten bildiğini söyler — böylece
`--fail-on-new` kullanan bir CI hattı yalnızca gerçekten bir şey kötüye
gittiğinde kırmızıya döner.

### Kurulum

**Python 3.9 veya üstü** gerekir. Gerisi, hangi modülleri istediğine bağlı
olarak opsiyoneldir:

| İstediğin... | Gereken |
|---|---|
| Temel kontroller (headers, CORS, içerik keşfi) | Sadece Python + pip |
| DNS/e-posta güvenliği (`dns`) ve mail (`mail`) kontrolleri | `[dns]` extra |
| Port taraması, TLS denetimi, nuclei şablonları (`ports`/`tls`/`web`) | Docker **ya da** araçların native kurulu olması |

**Seçenek A — klonla ve kur (ilk deneme için önerilen):**

```bash
git clone https://github.com/m0Corut/recon-orchestrator
cd recon-orchestrator
pip install ".[dns]"          # dns/mail modülleri gerekmiyorsa [dns]'i çıkar
```

Bu, PATH'ine bir `recon` komutu kurar.

**Seçenek B — PyPI'dan kur (klonlamaya gerek yok):**

```bash
pip install "recon-orchestrator[dns]"
```

**Seçenek C — Docker imajı (yerel kurulum sıfır, araçlar dahil):**

Python paketleri kurmak veya tek tek araç imajlarını çekmek istemiyorsan,
hepsi-bir-arada imajı kullan. nmap, nuclei ve testssl.sh'ı container içinde
native binary olarak barındırır, yani *sadece* Docker'ın kendisi gerekir:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/m0corut/recon-orchestrator \
  https://ornek.com --authorized
```

**Kurulumunu kontrol etmek:** kurduktan sonra `recon doctor` çalıştır —
tam olarak hangi araçları ve opsiyonel paketleri görebildiğini söyler, böylece
hangi modüllerin gerçekten çalışacağını önceden bilirsin.

### Adım adım ilk tarama

```bash
recon https://ornek.com --authorized
```

- `https://ornek.com` — **kendi siten**, ya da test etmek için yazılı iznin
  olan bir site. Araç şu olmadan çalışmayı reddeder:
- `--authorized` — bu hedefi test etmeye yetkili olduğunun açık onayı. Bu
  kontrolün etrafından dolanmanın bir yolu yok; bilerek konmuş bir engeldir.

Göreceğin şey: her modül başlarken bir ilerleme satırı, sonra
`3 info, 2 low, 1 medium` gibi bir özet satırı ve rapor klasörünün yolu.
`recon_runs/ornek.com_<zaman>/report.html`'i tarayıcıda aç — üstte önem
dağılımı, filtrelenebilir bir bulgu tablosu, ve her bulgunun altında sade
dilde açıklama ve düzeltme önerisi var.

Docker çalışmıyorsa veya kurulu değilse, Docker tabanlı modüller için
`[~] ports: atlandı` göreceksin — tarama, çalışabilen modüllerle birlikte
yine tamamlanır, sadece bir araç eksik olduğu için asla tamamen durmaz.

**Daha yumuşak bir ilk deneme** — sadece Python dışında hiçbir şey
gerektirmeyen kontroller, aracı sıfır kurulumla denemek için iyi bir yol:

```bash
recon ornek.com -m headers,cors,content,dns --authorized
```

### Sürekli kullanım (CI)

Gerçek değer, bunu bir kere değil düzenli çalıştırdığında ortaya çıkar. Bunu
pratik kılan iki parça var:

```bash
# Build'i yalnızca YENİ ve en az "high" önemde bir şey çıktığında durdur.
# Aynı host için önceki çalıştırma otomatik olarak baz alınır.
recon https://ornek.com --authorized --fail-on-new high
```

Ya da yeniden kullanılabilir GitHub Action'ı ekle:

```yaml
- uses: m0Corut/recon-orchestrator@main
  with:
    target: https://staging.ornek.com
    modules: "headers,cors,content,dns"
    fail-on-new: "high"
```

Bu repodaki `.github/workflows/scan.yml`, kendi projene kopyalayabileceğin
çalışan bir örnektir (haftalık zamanlama + elle tetikleme).

**Kabul edilen riskler.** Bazı bulgular bilinir ve bilerek kabul edilir.
Bunları `.reconignore.yml` dosyasına yaz (otomatik okunur, ya da
`--suppress-file` ver). Her girdi bir gerekçe ister; isteğe bağlı `expires`
tarihi geçince bulgu geri gelir ve CI'ı yeniden kırar. Bastırılan bulgular
sayımlara ve `--fail-on*` kapılarına girmez ama her raporda "Bastırılanlar"
başlığı altında listelenir.

```yaml
- rule_id: headers.missing-csp        # glob kullanılabilir: "headers.*"
  reason: "CSP geçişi JIRA-123'te takip ediliyor"
  expires: 2027-01-31
- rule_id: ports.notable
  reason: "Redis yalnızca VPN'e açık"
  fingerprint: 3f2a9c...              # isteğe bağlı: yalnızca bu örnek
```

**Bildirimler.** Zamanlanmış tarama ancak biri sonucu görürse işe yarar.
`--notify-env RECON_WEBHOOK` bir ortam değişkeninden bir veya daha fazla
webhook adresi okur (virgülle ayrılmış) ve yalnızca `--notify-min-severity`
(varsayılan `medium`) ve üstünde YENİ bulgu varsa kısa bir mesaj gönderir.
Slack, Discord ve Telegram
(`https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>`) adresleri
otomatik tanınır; diğerlerine genel bir JSON gönderilir. Mesajlarda başlık ve
rule_id bulunur, kanıt asla bulunmaz.

### Her modül tam olarak ne kontrol ediyor

| Modül | Gereken | Ne arıyor |
|-------|---------|-----------|
| `headers` | hiçbir şey | Eksik güvenlik başlıkları (HSTS, CSP, X-Frame-Options, …), güvensiz cookie bayrakları, sunucu/framework sürüm sızıntıları |
| `cors` | hiçbir şey | Saldırgan kontrolündeki bir Origin'i geri yansıtan CORS politikası, özellikle credentials ile birlikte |
| `content` | hiçbir şey | Yanlışlıkla açık bırakılmış dosya ve yollar (`.env`, `.git/config`, yedek dump'ları, debug endpoint'leri) |
| `dns` | `[dns]` extra | Eksik/zayıf SPF/DMARC (e-posta sahteciliği koruması), eksik DKIM, eksik CAA |
| `ports` | Docker ya da nmap | Hangi portların açık olduğu ve riskli bir servisin (veritabanı, Redis, RDP, …) internetten erişilebilir olup olmadığı |
| `tls` | Docker ya da testssl.sh | Eski TLS sürümleri ve zayıf şifreleyici setleri |
| `web` | Docker ya da nuclei | Bilinen CVE'ler, açık paneller ve yanlış yapılandırmalar için binlerce topluluk imzası |
| `authz` | senin verdiğin bir session cookie/token | Giriş gerektirmesi gereken sayfaların gerçekten girişsiz erişilip erişilemediği (salt-okunur — sadece GET/HEAD, form göndermez) |
| `openapi` | bir OpenAPI/Swagger şeması | Şemanın kimlik doğrulama gerektirdiğini söylediği endpoint'lerin gerçekten kimliksiz erişilip erişilemediği |
| `mail` | `[dns]` extra | Mail sunucunun STARTTLS sunup sunmadığı, MTA-STS/TLS-RPT'nin yapılandırılıp yapılandırılmadığı |

Bu listeyi ve her modülün güncel açıklamasını görmek için istediğin an
`recon modules` çalıştır.

### Göz atılacak kullanışlı bayraklar

```bash
--lang tr                     # Türkçe rapor metni (varsayılan: İngilizce)
--format html,json            # hangi rapor dosyalarının yazılacağını seç
--scope "api.x.com,*.cdn.x.com"  # hedefin dışında ek host'lara izin ver
--rate 10                     # production hedefte daha nazik ol
--jobs 2 / --serial           # modül paralelliğini sınırla veya kapat
--config recon.yaml           # hedefleri/ayarları bir YAML dosyasından oku (üretmek için recon init)
--runner native|docker|auto   # dış araçların nasıl çalıştırılacağı
--analyst anthropic           # opsiyonel AI yönetici özeti (opt-in, API anahtarı gerekir)
--github-issues org/repo      # opsiyonel: her yeni bulgu için bir GitHub issue aç
```

Her bayrağın tam detayı: `recon --help`.

### Mimari (katkıda bulunanlar için)

```
recon/
├── cli.py              # argüman ayrıştırma, config birleştirme, rapor yazımı
├── engine.py           # modülleri zamanlar, paralel çalıştırır, tekilleştirir
├── context.py          # ScanContext: her modülle paylaşılan tipli ayarlar
├── scope.py            # izin listesi + redirect-güvenli HTTP yardımcısı
├── ratelimit.py         # ortak, toplam hız sınırlayıcı
├── runner.py            # "bu dış aracı çalıştır" işlemini Docker ya da native binary üzerinden soyutlar
├── diff.py              # iki çalıştırma arasında parmak izi tabanlı karşılaştırma
├── config.py            # YAML yapılandırma dosyası yükleme/doğrulama
├── findings.py          # Finding/ScanResult veri modeli (rule_id, fingerprint, önem)
├── i18n.py              # İngilizce metin + Türkçe çeviri kataloğu
├── report.py / report_html.py   # Markdown / JSON / SARIF / HTML üreticiler
├── analyst/             # opsiyonel LLM özeti (opt-in, düz HTTP, SDK yok)
├── integrations/github.py       # opsiyonel GitHub issue oluşturma
└── modules/             # her kontrol için bir dosya; her biri NAME, NEEDS_DOCKER, run() verir
```

Modül eklemek için: `recon/modules/<ad>.py` içinde `NAME`, `NEEDS_DOCKER` ve
`run(target, ctx) -> list[Finding]` sağla; `recon/modules/__init__.py`'ye
kaydet; bulgu metnini İngilizce ve kararlı bir `rule_id` ile yaz, Türkçe
çeviriyi `recon/i18n.py`'ye ekle; araç çıktısı ayrıştırmasını ayrı bir saf
fonksiyonda tut (Docker ya da ağ olmadan test edilebilsin); `tests/` altına
test ekle.

### Kararlılık, geliştirme, lisans

CLI bayrakları ve `report.json` şeması
([docs/report.schema.json](docs/report.schema.json)) v1.0'dan itibaren
kararlıdır; kırıcı değişiklikler yeni bir ana sürümle ve CHANGELOG girdisiyle
gelir.

```bash
pip install -e ".[dev]"
ruff check recon/ tests/ && mypy recon/ && pytest -q
```

Her push/PR bu aynı kontrolü Python 3.9–3.13'te çalıştırır. Bir modül eklemek
veya hata düzeltmek için [CONTRIBUTING.md](CONTRIBUTING.md)'ye bak.

Apache-2.0 altında lisanslıdır — bkz. [LICENSE](LICENSE).
[nmap](https://nmap.org), [nuclei](https://github.com/projectdiscovery/nuclei)
ve [testssl.sh](https://github.com/drwetter/testssl.sh) üzerine kuruludur; bu
proje bu araçları yönetir, yerlerine geçmez.

### ⚠️ Yasal

Bu araç, verdiğin hedefe gerçek ağ istekleri gönderir. Yalnızca **sahibi
olduğun** veya test etmek için **yazılı iznin olan** sistemlerde kullan.
Yetkisiz tarama çoğu ülkede yasa dışıdır — sorumluluk tamamen sana aittir.
`--authorized` bayrağı, bu onayı bilinçli vermeden yanlışlıkla bir tarama
çalıştıramayasın diye özellikle oraya konmuştur.
