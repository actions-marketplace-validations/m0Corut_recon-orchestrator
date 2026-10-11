# Güvenlik Politikası

## Amaç ve yetkili kullanım

`recon-orchestrator`, **yalnızca sahibi olduğunuz veya test etmek için yazılı
izniniz olan** sistemlerde kullanılmak üzere tasarlanmıştır. Araç hedefe gerçek
istekler gönderir. Yetkisiz tarama çoğu ülkede suçtur; sorumluluk tamamen
kullanıcıya aittir. Araç, `--authorized` bayrağı olmadan çalışmaz ve varsayılan
olarak yalnızca hedef host'a istek atar (bkz. `--scope`).

## Zafiyet bildirimi

Bu araçta bir güvenlik açığı bulursanız:

- Lütfen **herkese açık issue açmadan önce** GitHub Security Advisories üzerinden
  (repo → Security → Report a vulnerability) özel bildirim yapın.
- Açığın sınıfını, etkisini ve yeniden üretme adımlarını paylaşın; çalışan bir
  exploit paylaşmanız gerekmez.
- Makul bir sürede (genellikle birkaç gün) yanıt vermeye çalışırız.

## Kapsam

- Araç kodundaki güvenlik hataları (örn. kapsam kontrolünü atlatma, komut
  enjeksiyonu, kullanıcı girdisinin güvensiz işlenmesi) kapsamdadır.
- Araçla **taradığınız** üçüncü taraf sistemlerdeki açıklar bu projenin kapsamı
  dışındadır.
