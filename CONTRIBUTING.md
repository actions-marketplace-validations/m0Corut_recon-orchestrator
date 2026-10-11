# Katkı Rehberi

Katkılar memnuniyetle karşılanır. Küçük düzeltmeler için doğrudan PR açabilir,
daha büyük değişiklikler için önce bir issue ile tartışabilirsiniz.

## Geliştirme ortamı

```bash
git clone https://github.com/m0Corut/recon-orchestrator
cd recon-orchestrator
pip install -e ".[dev]"
pre-commit install   # opsiyonel
```

## Göndermeden önce

```bash
ruff check recon/ tests/
mypy recon/
pytest -q
```

Üçü de yeşil olmalı; CI her push/PR'da aynı kontrolleri Python 3.9–3.13'te çalıştırır.

## Yeni modül ekleme

1. `recon/modules/<ad>.py` oluştur; şunları ver:
   - `NAME`, `NEEDS_DOCKER`
   - `run(target, ctx) -> list[Finding]`
   - Araç çıktısını ayrıştıran **saf bir fonksiyon** (Docker/ağ olmadan test
     edilebilsin), örn. `parse_<tool>(output) -> list[Finding]`.
2. `recon/modules/__init__.py` registry'sine bir `ModuleSpec` ekle.
3. Her bulguya kararlı bir `rule_id` ver; insan-okur metni İngilizce yaz ve
   Türkçe çevirisini `recon/i18n.py` kataloğuna ekle (`msg_key` + `params`).
4. Ağ/HTTP yapan modüller `recon.scope.scoped_get` kullanmalı (kapsam güvenliği).
5. `tests/` altında fixture tabanlı test ekle.

## Kurallar

- Araç yalnızca yetkili, non-destructive tarama içindir. Yıkıcı/intrusive
  davranış (DoS, veri değiştirme, exploit çalıştırma) eklemeyin.
- Varsayılan güvenli olmalı: yeni özellikler kapsam ve yetki kontrollerini
  atlamamalı.

Lisans: katkılarınız Apache-2.0 altında kabul edilir.
