# CLAUDE.md — server-ip-rotation

راهنمای کار روی این ریپو. فایل سراسری `~/.claude/CLAUDE.md` قواعد عمومی سادگی و بازاستفاده را
پوشش می‌دهد و اینجا تکرار نمی‌شود.

## این ریپو چیست

یک ابزار، یک کار: **عوض‌کردن Primary IPv4 یک نود در Hetzner Cloud**، با checkpoint و راه
برگشت. از ریپوی Ansible پروژه‌ی **shikoonet** در ۲۰۲۶-۰۸-۲۷ جدا شد تا روی GitLab CI/CD برود.

نیمه‌ی DNS **جدا نشد** و همان‌جا ماند: مرحله‌ی `ansible_done` داخل یک checkout از shikoonet
دستور `make ip-change HOST=<alias>` را اجرا می‌کند. مسیر آن checkout در `ansible.repo_dir`
داخل `rotation.yml` است، و در CI جاب `dns` آن را clone می‌کند.

## ⚠ این ابزار هرگز روی سرور واقعی اجرا نشده

نوشته‌شده ۲۰۲۶-۰۸-۲۶ با تست آفلاین کامل و **صفر فراخوانی زنده‌ی API**. به معنای این ریپو یعنی
**تست‌نشده** — با همین کلمه.

و `--check` اینجا کمکی نمی‌کند: **ماژول‌های hcloud در check mode هیچ action واقعی نمی‌سازند**،
پس ترتیب stop → detach → attach → start اصلاً اعتبارسنجی نمی‌شود. اولین اجرای زنده — حتی یک
`plan` با توکن واقعی — تأیید جداگانه‌ی کاربر می‌خواهد.

## قانون اول: هیچ‌چیز حذف نمی‌شود

نه سرور، نه Primary IP، نه رکورد DNS. بعد از rollback آدرس **نو** نگه داشته می‌شود و بعد از
موفقیت آدرس **قدیم** — هر دو هزینه دارند و پاک‌کردنشان تصمیم جدا و تأیید جداست.

`state: absent` در `hcloud_step.yml` وجود ندارد و `tests/contract.yml` این را با خواندن خود
فایل assert می‌کند. محافظت واقعی این است: چیزی که وجود ندارد نمی‌تواند اجرا شود.

## تأیید، شماره‌ی خود سرور است نه `true`

`SERVER_ID` باید دقیقاً با `server.id` در کانفیگ برابر باشد. «هرچه کانفیگ شده را بچرخان»
هیچ املایی ندارد. `make ip-rotate-plan` شماره را چاپ می‌کند.

## نقشه

| فایل | نقش |
|---|---|
| `rotate.py` | ماشین حالت (`STEPS`)، checkpoint، CLI، `--self-test` |
| `providers.py` | `HcloudProvider` — تنها لایه‌ای که با ارائه‌دهنده حرف می‌زند، از پشت seam‌ی به‌نام `runner` |
| `ansible_adapter.py` | مکث inventory و `make ip-change HOST=<alias>` |
| `hcloud_step.yml` | **تنها فایلی که می‌تواند چیزی را در هتزنر عوض کند.** یک `op` در هر اجرا |
| `tests/test_rotation.py` | رفتار — ماشین حالت، جدول rollback، resume از هر checkpoint |
| `tests/contract.yml` | قرارداد — منبع را به‌عنوان **متن** و به‌عنوان **YAML** می‌خواند |
| `.github/workflows/run.yml` | تنها workflow: روی push فقط تست آفلاین؛ عملیات‌ها با دراپ‌داون `operation` در dispatch. گیت انسانی، required reviewer روی environment است |

هیچ کلاینت HTTP به هتزنر در پایتون این پروژه نیست — هر فراخوانی ارائه‌دهنده یک ساب‌پروسس
`ansible-playbook hcloud_step.yml` است.

## دستورها

```bash
make test                                    # unittest + --self-test + قرارداد. آفلاین، رایگان
make lint
make ip-rotate-plan                          # فقط‌خواندنی
make ip-rotate-swap    SERVER_ID=<id>        # فقط نیمه‌ی ارائه‌دهنده، قبل از ویرایش inventory می‌ایستد
make ip-rotate-apply   SERVER_ID=<id>        # سرتاسر، تعاملی
make ip-rotate-resume  TXID=<t> SERVER_ID=<id>
make ip-rotate-rollback TXID=<t> SERVER_ID=<id>
make ip-rotate-status  TXID=<t>
```

`HCLOUD_TOKEN` باید export شده باشد. **هرگز به‌عنوان آرگومان پاس نمی‌شود.**

## `--until` و مرز CD

`--until` فقط `connectivity_ok` و `ansible_done` را می‌پذیرد (`PAUSABLE` در `rotate.py`) —
دو حالتی که باکس روشن و قابل‌دسترس است. **این لیست را گشاد نکنید:** هر حالت دیگری وسط swap
است و «اینجا بایست» آنجا یعنی یک نود بدون هیچ آدرسی.

`EXIT_PAUSED` عمداً ۶ است و نه ۴ (`EXIT_ESCALATED`). یک مرز عادی pipeline که قرمز نشان داده
شود، همان مکانیزمی است که باعث می‌شود escalation واقعی دیده نشود — همان درسی که در shikoonet
با «کانال آلرت هفته‌ها قرمز بود» پرداخت شد.

## گیت انسانی در CI

ابزار عمداً وسط کار می‌ایستد تا انسان `inventory/hosts.yml` را ویرایش کند. pipeline آن را
حذف نمی‌کند، **جابه‌جا می‌کند**:

- مکث انسانی → `environment: hetzner-production` با **required reviewer**. GitHub دکمه‌ی
  manual per-job ندارد؛ environment محافظت‌شده همان دکمه است و run در حالت *Waiting* می‌ماند
- ویرایش inventory → یک **کامیت** در ریپوی shikoonet، و جاب `dns` قبل از جواب‌دادن به prompt
  همان checkout را برای آدرس جدید **grep می‌کند**
- `rollback` یک workflow **جدا** است نه یک جاب: برخلاف GitLab، روی یک run تمام‌شده‌ی GitHub
  هیچ دکمه‌ای باقی نمی‌ماند. `txid` و `run_id` می‌گیرد و artifact چک‌پوینت را پایین می‌کشد
- `HCLOUD_TOKEN` روی **environment** بگذارید نه روی ریپو — سکرت environment فقط برای جابی
  خوانده می‌شود که از reviewer آن رد شده باشد

پس `yes` در آن جاب حدس نیست؛ حقیقتی است که جاب از گیت دوباره استخراج کرده.

**قاعده‌ی عمومی: وقتی یک گیت انسانی باید از اتوماسیون جان سالم به در ببرد، prompt را با چکی
جایگزین کنید که اتوماسیون بتواند رویش شکست بخورد. هرگز با یک فرض.**

## قراردادها

- هر رفتار جدید یک تست در `tests/test_rotation.py` می‌گیرد. `FakeHcloud` جای
  `ansible-playbook hcloud_step.yml` می‌نشیند — دومی در تست صدا زده نمی‌شود.
- تست رفتاری نمی‌تواند یک `state: absent` را در شاخه‌ای که هیچ تستی اجرایش نمی‌کند بگیرد.
  `tests/contract.yml` برای همین است. **هر دو نوع را نگه دارید.**
- `redact()` روی کل checkpoint موقع `save()` اجرا می‌شود، نه در تولیدکننده‌ی هر فیلد.
- `rotation.yml` هرگز کامیت نمی‌شود — شماره‌ی سرور واقعی و اثرانگشت پروژه‌ی واقعی را پین می‌کند.

## ایجنت‌ها و اسکیل‌ها

```
rotation-build   (opus) ──▶ rotation-explorer
rotation-verify  (opus) ──▶ rotation-explorer
```

`rotation-explorer` هیچ `Agent(...)` ندارد، پس برگ است و درخت عمیق‌تر نمی‌شود.

**دانش تخصصی دامنه در ایجنت نمی‌نشیند، در اسکیل می‌نشیند:**

| اسکیل | چه وقت |
|---|---|
| `hetzner-cloud` | هر دست‌زدنی به `hcloud_step.yml` یا هر task ماژول hcloud |
| `ip-rotation-runbook` | اجرای یک چرخش، خواندن checkpoint، تصمیم resume در برابر rollback |
| `python-ansible-adapter` | ویرایش `rotate.py` / `providers.py` / `ansible_adapter.py`، افزودن op جدید |

## بعد از هر چرخش

`make monitoring-doctor` در ریپوی shikoonet. تنها چیزی است که نودی را می‌بیند که بالاست ولی
بی‌صدا مانیتور نمی‌شود — و داشبورد سبز برای باکسی که scrape نمی‌شود بدتر از یک آلرت down است.
