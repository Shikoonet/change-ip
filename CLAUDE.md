# CLAUDE.md — server-ip-rotation

راهنمای کار روی این ریپو. فایل سراسری `~/.claude/CLAUDE.md` قواعد عمومی سادگی و بازاستفاده را
پوشش می‌دهد و اینجا تکرار نمی‌شود.

## این ریپو چیست

یک ابزار، یک کار: **عوض‌کردن Primary IPv4 یک نود در Hetzner Cloud**، با checkpoint و راه
برگشت. از ریپوی Ansible پروژه‌ی **shikoonet** در ۲۰۲۶-۰۸-۲۷ جدا شد تا روی GitLab CI/CD برود.

نیمه‌ی DNS **جدا نشد** و همان‌جا ماند: مرحله‌ی `ansible_done` داخل یک checkout از shikoonet
دستور `make ip-change HOST=<alias>` را اجرا می‌کند. مسیر آن checkout در `ansible.repo_dir`
داخل `rotation.yml` است، و در CI جاب `dns` آن را clone می‌کند.

## وضعیت اجرای زنده

**نیمه‌ی هتزنر روی سرور واقعی اجرا شده و کار کرد** — ۲۰۲۶-۰۹-۰۸، سرور `165084788`
(`ubuntu-2gb-fsn1-1`, fsn1) از `188.245.127.27` رفت روی `138.199.229.27` در ~۹۰ ثانیه.
ترتیب allocate → protect → stop → detach → attach → start → probe کامل اجرا شد و در
`connectivity_ok` با `outcome: paused` و کد خروج ۶ ایستاد. از بیرون هم مستقل تأیید شد،
نه فقط از لاگ. پس `hcloud_step.yml` دیگر «تست‌نشده» نیست.

**نیمه‌ی DNS: `discover` زنده اجرا شده، `apply`/`rollback` هنوز نه.** ۲۰۲۶-۰۹-۰۸ عملیات
`dns-scan` اولین تماس زنده‌ی این ریپو با Cloudflare بود — یک `discover` واقعی روی هر دو
حساب (`ok=18 failed=0`) روی `46.62.161.237`. پس مسیر خواندن (zone list، pagination،
content scan، token per account) اثبات شده. مسیر **PATCH** — `apply` و `rollback` در
`cloudflare_replace_ip_step.yml` — هنوز صفر فراخوانی زنده دارد. به معنای این ریپو یعنی
**تست‌نشده**، با همین کلمه.

دومین چرخش زنده هم همان روز: `ubuntu-4gb-hel1-2` (`165200692`, hel1) از `46.62.161.237`
به `89.167.72.62`. نامش را کسی تایپ نکرد — `plan` روی placeholder رد کرد و نام واقعی را
در پیام رد گفت. برای هر باکس جدید همین کار را بکن.

و `--check` اینجا کمکی نمی‌کند: **ماژول‌های hcloud در check mode هیچ action واقعی نمی‌سازند**،
پس هیچ ترتیبی با آن اعتبارسنجی نمی‌شود. اولین اجرای زنده‌ی نیمه‌ی DNS تأیید جداگانه‌ی کاربر
می‌خواهد.

## قانون اول (بازنویسی ۲۰۲۶-۰۹-۰۸): فقط یک حذف، فقط بعد از پایان، فقط روی آدرس بی‌صاحب

تا امروز هیچ‌چیز حذف نمی‌شد. سه Primary IP نگه‌داشته‌شده روی صورت‌حساب جمع شد و اپراتور
قانون را عوض کرد: آدرس قدیم بعد از چرخش موفق **آزاد می‌شود**. آنچه از قانون قبلی مانده،
شکلِ آن حذف است:

- **یک** `state: absent` در کل `hcloud_step.yml`، فقط داخل op `release`، و فقط بعد از یک
  خواندن تازه که assert می‌کند آدرس به **هیچ‌چیز** وصل نیست. `tests/contract.yml` این را با
  خواندن فایل **به‌عنوان YAML** چک می‌کند، نه regex — یک `state: absent` دوم، یا یکی بدون آن
  assert، contract را قرمز می‌کند.
- `rotate.py release-old-ip --txid` تنها راه رسیدن به آن op است. رد می‌کند مگر: کانفیگ
  `old_ip.retention: release` بگوید؛ تراکنش تمام شده باشد (`done`، یا `connectivity_ok` زیر
  `provider_only`); سرور همین حالا روی آدرس نو باشد؛ آدرس قدیم هنوز همان آدرس باشد و
  assignee نداشته باشد؛ قبلاً آزاد نشده باشد. هر کدام از یک خواندن تازه، هر شکست یک رد است
  نه یک skip.
- در `run.yml` فقط جاب `swap` (همان reviewer که swap را تأیید کرد) و فقط برای
  `provider-only` آن را صدا می‌زند، و `retention` را از خود `rotation.yml` در زمان اجرا
  می‌خواند. کانفیگ `keep` با exit 0 و بدون حذف رد می‌شود.
- **بعد از release، rollback به آدرس قبلی وجود ندارد.** این هزینه‌ای است که اپراتور پذیرفت.

سرور و رکورد DNS همچنان هرگز حذف نمی‌شوند.

## تأیید، شماره‌ی خود سرور است نه `true`

`SERVER_ID` باید دقیقاً با `server.id` در کانفیگ برابر باشد. «هرچه کانفیگ شده را بچرخان»
هیچ املایی ندارد. `make ip-rotate-plan` شماره را چاپ می‌کند.

## آدرس روی فرم است، نه در کانفیگ (از ۲۰۲۶-۰۹-۰۸)

`server.expected_ipv4` برای hcloud **اختیاری** است و در `ROTATION_CONFIG` نیست. آدرس هر بار
روی فرم dispatch تایپ می‌شود و `rotate.py --expect-ipv4` آن را در برابر یک **خواندن زنده**
assert می‌کند.

چرا: آدرس تنها فیلدی است که یک چرخش عوضش می‌کند. پین‌کردنش در secret یعنی بعد از هر اجرای
موفق یک انسان باید secret را روی دو environment ویرایش کند وگرنه dispatch بعدی رد می‌شود.
این دقیقاً یک بار اتفاق افتاد و یک اجرای گیج‌کننده هزینه داشت.

مقایسه با خواندن زنده **قوی‌تر** از مقایسه با کانفیگ است: قبلاً فقط ثابت می‌شد دو کپی از یک
حدس با هم می‌خوانند؛ حالا حدس با واقعیت سنجیده می‌شود، پس هم typo را می‌گیرد هم سروری که
بیرون از این ابزار جابه‌جا شده. اگر هیچ آدرسی هم تایپ نشود، `id` و `name` و `location` و
`project_fingerprint` همچنان باید بخوانند و چک‌پوینت آدرس واقعی را ثبت می‌کند.

⚠ برای **dataforest** همچنان اجباری است، چون آنجا load-bearing است: یک Seed چند آدرس همزمان
دارد و این تعیین می‌کند کدام `OLD_IP` است. نامتقارنی عمدی است.

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

عملیات‌های `workflow_dispatch` در `run.yml`: `plan`، `change-ip`، `provider-only`،
`dns-scan`، `rollback`، `finalize`.

`dns-scan` فقط‌خواندنی است و به سؤالی جواب می‌دهد که هیچ ابزاری نداشت: **چه چیزی هنوز به
این آدرس اشاره می‌کند؟** هر zone را برای رکوردهای A با آن محتوا می‌گردد (هر حساب Cloudflare
جدا، با توکن خودش)، فهرست را چاپ و به‌عنوان artifact ذخیره می‌کند. قبل از آزادکردن یک
Primary IP لازم است — هتزنر آدرس رهاشده را می‌تواند به مشتری دیگری بدهد و آن‌وقت دامنه‌ی تو
به سرور یک غریبه اشاره می‌کند. هیچ PATCHی نمی‌زند؛ `discover` فقط GET است و
`test_dns_scan_is_read_only` وجود `apply`/`rollback` را در آن جاب رد می‌کند.

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

## allowlist یک **کف** است، نه فهرست کامل (از ۲۰۲۶-۰۹-۰۸)

`cloudflare.allowed_records` حداقلی است که باید پیدا شود، نه سقف چیزی که عوض می‌شود.
discover دو کار می‌کند: نام‌های allowlist را resolve می‌کند، **و** از هر zone می‌پرسد چه
رکورد A‌ای همین حالا محتوایش `old_ip` است (`?type=A&content=<ip>`، فیلتر سمت سرور، یک
درخواست per-zone). اتحاد این دو، با dedup روی `record_id`، manifest را می‌سازد.

اگر یکی از نام‌های allowlist برنگردد، preflight می‌ایستد. رکوردهای اضافه‌ی بالای کف مجازند
و **همان هدف این تغییر است**.

چرا عوض شد: allowlist دستی بیات می‌شود. یک رکورد A که از موبایل ساخته شده بود در کانفیگ
نبود، پس چرخش هشت نام لیست‌شده را برد و آن یکی را روی آدرس مرده جا گذاشت — و run خودش را
موفق اعلام کرد، چون طبق تعریف خودش کامل بود.

⚠ کف **بر اساس نام** assert می‌شود نه تعداد. هشت لیست‌شده، یکی غایب، دو تا stray پیدا شده
یعنی نُه ورودی، و یک چک `>= expected_count` تنها از آن رد می‌شد.
`test_floor_is_not_satisfied_by_strays_making_up_the_count` دقیقاً همین را می‌گیرد.

خاصیتی که دست‌نخورده ماند: manifest هنوز **قبل از** هر mutation روی provider ساخته می‌شود و
apply/rollback فقط همان record_idها را PATCH می‌زنند. اسکن تعیین می‌کند چه چیزی وارد manifest
شود، نه اینکه بعداً چه چیزی عوض شود.

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

### skip-defence ثابت در `_step_cloudflare_preflight`

اولین if-block `_step_cloudflare_preflight` (rotate.py:1416-1425) قبل از
هر lookup توکن پایان می‌یابد: manifest خالی، envelope با `skipped: True`، `return`.
هیچ تماسی به Cloudflare نمی‌خورد، هیچ env var توکنی نمی‌خواند. defence در خودِ rotate.py
ساختاری است، نه یک چک بعدی.

- source-level: `tests/contract.yml` عبارت `if self.provider_only: … cp["cloudflare_manifest"] = [] … return`
  را به ترتیب در خود rotate.py چک می‌کند. هر refactor که این ترتیب را به‌هم بزند، باید این تست
  را نیز به‌روز کند.
- behaviour-level: `tests/test_rotation.py::TestCloudflareFlow::test_provider_only_throwaway_opt_out_structurally_blocks_dns`
  ثابت می‌کند که در کل run، هیچ discover/apply/verify صدا زده نمی‌شود.
- سنجش operator-supplied server fixture:
  `tests/test_rotation.py::TestCloudflareFlow::test_provider_only_skip_with_real_server_fixture`
  همین ادعا را روی سرور هتزنر `#164897365 @ 188.245.32.133` (server اخیراً توسط
  operator تأیید شد) pin می‌کند تا یک regression که به یک سرور پیش‌فرض برمی‌گردد، شناسایی شود.

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
| `ROTATION_CONFIG` | env `hetzner-plan`، `hetzner-production` | محتوای `rotation.yml` (paste **بدون** `---` ابتدایی). **بدون `server.expected_ipv4`** — آدرس روی فرم dispatch می‌آید، پس این secret بعد از چرخش بیات نمی‌شود و دیگر هرگز لازم نیست دستی عوضش کنی. Actions هر خط را مستقل ماسک می‌کند و masking یک مرز نیست: مقدار خام و تبدیل‌شده را از لاگ و step summary دور نگه دار |
| `SHIKOONET_REPO` | repo | URL without credential in the URL itself; clone in job `dns` uses a temporary git credential helper that injects the token only for the one `git clone` call and is removed immediately after — never write the URL with token to `.git/config` and never leave the helper configured past the clone |
| `SSH_PRIVATE_KEY` | repo | فقط استپ `Resume the rotation in shikoonet` (جاب `dns`) |
| `ANSIBLE_VAULT_PASSWORD` | repo | vault شیکونِت، همان استپ |
| `CLOUDFLARE_API_TOKEN` | env `hetzner-production` (یا هر محیط دیگری که جاب dns نیاز دارد) | فقط استپ‌هایی که playbook Cloudflare را اجرا می‌کنند؛ گیت مثبت `==` مانع نشت توکن به provider-only می‌شود. **environment secret**, نه repo secret — یک repo secret readable توسط هر workflow در هر برنCH است. |

environmentها:
- `hetzner-plan` — جاب‌های `plan` و `verify` (فقط‌خواندنی). **بدون reviewer**
- `hetzner-production` — جاب‌های `swap`، `dns`، `rollback`. **با required reviewer از ۲۰۲۶-۰۹-۰۸**
- `cloudflare-production` — جاب `dns_scan` و مراحل DNS دیتافارست. **هنوز بدون reviewer**
- `dataforest-production` — مراحل provider دیتافارست. **هنوز بدون reviewer**

⚠ تا ۲۰۲۶-۰۹-۰۸ هیچ environmentی reviewer نداشت، در حالی که همین فایل آن را «دکمه‌ی
توقف» می‌نامید. protection را از API بخوان نه از این متن:
`gh api repos/Shikoonet/change-ip/environments/<env> --jq '.protection_rules'`

```bash
# وضعیت فعلی (live audit 2026-09-08):
gh secret list --repo Shikoonet/change-ip            # 0 سکرت repo-level — همه environment-scoped هستند
gh secret list --env dataforest-production --repo Shikoonet/change-ip   # DATAFOREST_API_TOKEN
gh secret list --env cloudflare-production --repo Shikoonet/change-ip  # CLOUDFLARE_API_TOKEN_ACCOUNT_A, _B
gh secret list --env hetzner-plan --repo Shikoonet/change-ip          # HCLOUD_TOKEN, ROTATION_CONFIG
gh secret list --env hetzner-production --repo Shikoonet/change-ip     # HCLOUD_TOKEN, ROTATION_CONFIG
gh api repos/Shikoonet/change-ip/environments   # 4 environment؛ فقط hetzner-production reviewer دارد
# چهار سکرت زیر **هنوز تعریف نشده‌اند** و باید قبل از اولین `Run workflow → change-ip` اضافه شوند:
#   CLOUDFLARE_API_TOKEN          (legacy single-account, on hetzner-production)
#   SHIKOONET_REPO                (on cloudflare-production + hetzner-production)
#   SSH_PRIVATE_KEY               (on cloudflare-production + hetzner-production)
#   ANSIBLE_VAULT_PASSWORD        (on cloudflare-production + hetzner-production)
# `bash scripts/setup-secrets.sh` این لیست را به‌صورت idempotent audit می‌کند
# و دقیقاً `gh secret set` commands مورد نیاز را چاپ می‌کند.
```

`HCLOUD_TOKEN` و `ROTATION_CONFIG` روی **environment** باشند نه روی repo — یک سکرت
repo-wide برای هر جابی روی هر برنچی قابل‌خواندن است. ماسک یک مرز نیست.

> **هشدار**: چهار سکرت بالا در حال حاضر missing هستند. CI آفلاین (push+PR) آن‌ها را لازم
> ندارد (مسیر dispatch اجرا نمی‌شود)، پس pipeline سبز می‌ماند؛ ولی **اولین** `Run workflow
> → change-ip` بدون `git clone` موفق یا `ssh` کار، شکست می‌خورد. قبل از اولین
> dispatch انسانی، `bash scripts/setup-secrets.sh` را اجرا کنید.

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
