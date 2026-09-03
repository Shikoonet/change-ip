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
| `cloudflare_replace_ip_step.yml` | **تنها فایلی که می‌تواند رکورد DNS را در Cloudflare PATCH کند.** چهار op (`discover`/`apply`/`rollback`/`verify`) با manifest واحد |
| `cloudflare_adapter.py` | دوری runner subprocess برای playbook، atomic tmpfile، redaction، رد توکن |
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

`--until` فقط `connectivity_ok` و `ansible_done` و `cloudflare_replaced` را می‌پذیرد (`PAUSABLE`
در `rotate.py`) — سه حالتی که باکس روشن و قابل‌دسترس است. **این لیست را گشاد نکنید:** هر حالت
دیگری وسط swap است و «اینجا بایست» آنجا یعنی یک نود بدون هیچ آدرسی.

## state flow جدید

```
confirmed → cloudflare_preflighted → new_ip_allocated → server_off
        → old_ip_unassigned → new_ip_assigned → server_on
        → connectivity_ok → ansible_done → cloudflare_replaced → done
```

`cloudflare_preflighted` اول می‌آید (پیش از هر mutation روی هتزنر): discover یک manifest
از رکوردهای A داخل allowlist می‌سازد و قبل از اینکه یک بیت روی هتزنر عوض شود آن را روی
چک‌پوینت persist می‌کند. `cloudflare_replaced` بعد از `ansible_done` می‌آید: PATCH فقط روی
record IDهای manifest، نه scan، نه discover ثانویه، نه expansion.

## allowlist (manifest، نه scan)

`cloudflare.allowed_records` در کانفیگ فهرست FQDNهایی است که این چرخش حق عوض‌کردنشان را
دارد. discover آن‌ها را resolve می‌کند، record_idهایشان را در manifest ذخیره می‌کند، و
apply/rollback فقط آن record_idها را PATCH می‌زنند. اگر در کانفیگ هشت FQDN لیست شده ولی
Cloudflare فقط شش تا برگرداند، preflight می‌ایستد — «نیمه‌ای که می‌بینم» نمی‌تواند
«نیمه‌ای که عوض می‌کنم» باشد.

## mutation-manifest برای rollback امن

هر PATCH روی یک record_id کاملاً مشخص روی manifest انجام می‌شود — نه روی نتیجه‌ی
discover ثانویه. اگر بین discover و apply انسانی رکوردی را ویرایش کرده باشد، apply با
validation_error (نه drift ساکت) شکست می‌خورد. rollback همان record_idهای manifest را
می‌گیرد و PATCH می‌کند و اگر یکی از آن‌ها هم‌اکنون محتوای شخص ثالث داشته باشد (یا اصلاً
نباشد)، در JSON خروجی `rollback_incomplete: true` می‌نویسد.

## توکن (از env، نه از argv، نه از checkpoint)

`CLOUDFLARE_API_TOKEN` از env؛ ماژول `ansible.builtin.uri` خودش هدر `Authorization` را
از آن می‌سازد. قرادرد آفلاین `no_log: true` روی هر task با `Authorization` را assert
می‌کند و `cloudflare_adapter.redact_tree()` در زمان نوشتن روی دیسک redaction انجام می‌دهد
تا یک field که فردا خروجی Ansible را حمل می‌کند نتواند نشت دهد.

## رفتار non-TTY

در غیاب TTY (CI، اجرای remote)، `inventory_step` و `inventory_rollback_step` همچنان
متن را پرینت می‌کنند ولی prompt در انتظار پاسخ نمی‌ماند. CI باید اپراتورِ معتبر شدن
inventory edit را با grep روی ریپوی shikoonet (همان که در جاب `dns` هست) ثابت کند، نه با
`yes` خودکار.

## preflight پیش از ارائه‌دهنده

`cloudflare_preflight` نخستین step بعد از `confirmed` است و حتی پیش از allocate هم
اجرا می‌شود. اگر Cloudflare token موجود نباشد، یا allowlist نامعتبر باشد، یا DNS خراب
باشد، ابزار **پیش از اینکه یک IP بیل شود** شکست می‌خورد. هزینه‌ی شکست preflight: پیام
stderr، نه یک node با آدرس سوخته.

## partial-failure recovery (rollback_incomplete)

اگر DNS rollback با موفقیت کامل نشود (یکی از رکوردها third-party، یا missing)، ابزار
outcome را `rollback_incomplete` می‌گذارد (کد خروج ۷، با `EXIT_ROLLED_BACK=5` و
`EXIT_ESCALATED=4` فرق دارد). آدرس روی سرور برگشته، اما DNS یا inventory تمام نشده؛
operator ادامه می‌دهد با خواندن checkpoint و پاک‌کردن بقیه‌ی رکوردها دستی.

## provider_only opt-out (برای throwaway test servers)

`cloudflare.mode: provider_only` در کانفیگ کل DNS half را ساختاری غیرفعال می‌کند.
ابزار در `connectivity_ok` pause می‌کند، حتی بدون `--until`. validate_config هر مقدار
دیگری را رد می‌کند چون «skip ساکت» و «pause اعلام‌شده» فرق دارد.

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

## سکرت‌ها و environmentها (قبل از اولین dispatch)

سکرت‌های workflow در `.github/workflows/run.yml` مستند شده‌اند؛ اینجا فقط چک‌لیست
است برای قبل از اولین `workflow_dispatch` زنده.

| نام | scope | استفاده |
|---|---|---|
| `HCLOUD_TOKEN` | env `hetzner-plan`، `hetzner-production` | فراخوانی hcloud در plan / swap / dns / verify / rollback |
| `ROTATION_CONFIG` | env `hetzner-plan`، `hetzner-production` | محتوای `rotation.yml` (paste **بدون** `---` ابتدایی؛ Actions هر خط را مستقل ماسک می‌کند — اما masking best-effort است، نه مر امنت;ی;.ی: structured data یا JSON یا XML YAML is not safe; keep the raw و transformed value out of logs and step summary) |
| `SHIKOONET_REPO` | repo | URL without credential in the URL itself; clone in job `dns` uses a temporary git credential helper that injects the token only for the one `git clone` call and is removed immediately after — never write the URL with token to `.git/config` and never leave the helper configured past the clone |
| `SSH_PRIVATE_KEY` | repo | فقط استپ `Resume the rotation in shikoonet` (جاب `dns`) |
| `ANSIBLE_VAULT_PASSWORD` | repo | vault شیکونِت، همان استپ |
| `CLOUDFLARE_API_TOKEN` | env `hetzner-production` (یا هر محیط دیگری که جاب dns نیاز دارد) | فقط استپ‌هایی که playbook Cloudflare را اجرا می‌کنند؛ گیت مثبت `==` مانع نشت توکن به provider-only می‌شود. **environment secret**, نه repo secret — یک repo secret readable توسط هر workflow در هر برنCH است. |

environmentها:
- `hetzner-plan` — جاب‌های `plan` و `verify` (فقط‌خواندنی)
- `hetzner-production` — جاب‌های `swap`، `dns`، `rollback` با required reviewer

```bash
gh secret list --repo Shikoonet/change-ip            # 5 سکرت repo-level
gh secret list --env hetzner-plan --repo Shikoonet/change-ip      # HCLOUD_TOKEN, ROTATION_CONFIG
gh secret list --env hetzner-production --repo Shikoonet/change-ip # همه‌ی توکن‌های production روی محیط production
gh api repos/Shikoonet/change-ip/environments        # 2 environment با reviewer
```

`HCLOUD_TOKEN` و `ROTATION_CONFIG` روی **environment** باشند نه روی repo — یک سکرت
repo-wide برای هر جابی روی هر برنچی قابل‌خواندن است. ماسک یک مرز نیست.

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
