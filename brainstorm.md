# brainstorm

Mình sẽ đi vào phần “cách nghĩ và cách làm” ở mức researcher: từ cách chọn bề mặt tấn công, đặt giả thuyết, tìm primitive, đến cách chain impact — nhưng giữ trong phạm vi lab/authorized research.

Thought for 21s

Để săn 0day RCE nghiêm trọng, mindset không phải là “grep sink nguy hiểm”, mà là **tìm nơi hệ thống tự tạo ra quyền năng nguy hiểm từ dữ liệu tưởng như vô hại**.

Mình chia thành 3 phần: **brainstorm**, **mindset**, và **approach thực chiến trong lab/authorized scope**.

---

## 1. Mindset cốt lõi: đừng tìm bug, hãy tìm “sự thật bị phá”

Bug hunter thường hỏi:

> “Input user có tới sink nguy hiểm không?”
> 

Researcher mạnh hỏi:

> “Hệ thống tin điều gì là đúng? Và có cách nào làm điều đó sai không?”
> 

Ví dụ các “sự thật” mà hệ thống thường tin:

- File upload là inert, không thể trở thành code.
- User thường không chạm được admin-only path.
- Worker chỉ xử lý task đến từ trusted producer.
- Template chỉ render nội dung trusted.
- URL đã validate rồi thì internal service có thể dùng an toàn.
- Object đã serialize/deserialize rồi vẫn giữ đúng type kỳ vọng.
- Auth check ở gateway là đủ cho backend.
- Extension/plugin chỉ được cài bởi admin.
- Cache key, route key, tenant key không thể bị người dùng điều khiển sai ngữ cảnh.

0day nghiêm trọng thường xuất hiện khi một trong các giả định này **đúng ở layer A nhưng sai ở layer B**.

Tư duy nên chuyển từ:

> source → sink
> 

sang:

> assumption → boundary → primitive → chain → impact
> 

---

## 2. Công thức brainstorm cấp researcher

Khi nhìn một target, đừng bắt đầu bằng “có eval không?”. Bắt đầu bằng bản đồ này:

```
User-controlled things
        ↓
Where are they stored?
        ↓
Who later consumes them?
        ↓
Are they re-parsed, normalized, trusted, executed, routed, or loaded?
        ↓
Can that create a primitive?
        ↓
Can primitive chain to RCE / auth bypass / data access?
```

Câu hỏi quan trọng nhất:

> “Dữ liệu user không nguy hiểm ở bước 1, nhưng ở bước 5 có bị diễn giải lại thành thứ nguy hiểm không?”
> 

Ví dụ ở mức khái niệm:

- Một string ban đầu chỉ là filename.
- Sau đó nó thành path.
- Sau đó path được worker đọc.
- Sau đó file được load như config/template/plugin/cache.
- Sau đó logic nội bộ dùng nội dung đó trong context có privilege cao hơn.

RCE thường không nằm ở string ban đầu. Nó nằm ở **lần diễn giải lại cuối cùng**.

---

## 3. Brainstorm theo “primitive”, không theo bug class

Thay vì hỏi “có RCE không?”, hãy hỏi:

### Primitive 1: Điều khiển đường dẫn

Bạn có kiểm soát được tên file, thư mục, extension, archive entry, import path, plugin path, cache path, temporary path không?

Sau đó hỏi:

> “Có component nào tự động đọc/load/compile/execute thứ nằm ở path đó không?”
> 

Điểm cần để ý:

- upload/import/export
- backup/restore
- theme/template
- plugin/extension
- report generation
- archive extraction
- localization file
- cache file
- log file
- config file
- migration script
- model/package artifact

Không phải file write nào cũng nghiêm trọng. Nhưng file write trở nên nguy hiểm nếu nó chạm được vào **autoload location**.

---

### Primitive 2: Điều khiển nội dung được parse lại

Bạn có đưa được dữ liệu vào một format mà backend sẽ parse lần hai không?

Ví dụ các vùng hay có bug:

- YAML/JSON/XML/TOML/protobuf
- archive formats
- document converters
- image metadata
- markdown/renderers
- template syntax
- serialized objects
- package manifests
- CI/CD config
- infrastructure config
- rule engines
- workflow definitions

Câu hỏi brainstorm:

> “Validator parse bằng parser nào? Consumer parse bằng parser nào? Hai parser có hiểu giống nhau không?”
> 

Rất nhiều bug nghiêm trọng nằm ở parser differential:

```
validator sees safe
consumer sees dangerous
```

---

### Primitive 3: Điều khiển URL / request nội bộ

Đừng chỉ nghĩ SSRF là “đọc metadata”. Hãy nghĩ sâu hơn:

> “Nếu mình làm server gửi request nội bộ, request đó có side effect không?”
> 

Các câu hỏi:

- Internal endpoint có action không cần auth vì tin source nội bộ không?
- Có service admin chỉ bind internal network không?
- Có webhook receiver, job trigger, cache purge, config reload không?
- Có service dùng HTTP method, header, redirect, DNS, proxy khác nhau không?
- Có chỗ nào response không cần đọc nhưng side effect vẫn xảy ra không?

Primitive SSRF mạnh không nhất thiết cần đọc response. Đôi khi chỉ cần **kích hoạt hành động nội bộ**.

---

### Primitive 4: Điều khiển object/type

Trong hệ thống có serialization, queue, cache, session, RPC, message bus, task runner, câu hỏi không phải chỉ là:

> “Có deserialize user input không?”
> 

Mà là:

> “Có nơi nào object được tạo ở context low-trust nhưng được tiêu thụ ở context high-trust không?”
> 

Brainstorm:

- Object type có được whitelist thật không?
- Type metadata có được user ảnh hưởng gián tiếp không?
- Message queue có phân biệt producer trusted/untrusted không?
- Cache/session có thể bị poisoning không?
- Worker có assume message đã được validate ở API layer không?
- Version mismatch có làm consumer hiểu khác producer không?

RCE class này thường rất mạnh vì worker/background service hay chạy với quyền cao hơn request user.

---

### Primitive 5: Điều khiển template / expression / rule

Rất nhiều sản phẩm enterprise có feature kiểu:

- report template
- notification template
- email template
- workflow rule
- automation script
- formula field
- transformation rule
- policy engine
- custom expression
- dashboard widget

Mindset researcher:

> “Feature này được thiết kế để người dùng tùy biến logic. Ranh giới giữa data và code nằm ở đâu?”
> 

Câu hỏi:

- User thường có được tạo template không?
- Template có helper/function nguy hiểm không?
- Có sandbox không? Sandbox chặn bằng denylist hay capability model?
- Template được render ở frontend hay backend?
- Render chạy với quyền của ai?
- Có thể include/import template khác không?
- Có thể đọc environment/config/secret không?
- Có cache compiled template không?

RCE thường đến từ nơi sản phẩm **cố tình cho phép extensibility**, nhưng kiểm soát capability không đủ chặt.

---

## 4. Cách chọn nơi đào: ma trận ưu tiên

Không phải chỗ nào cũng đáng tốn 2 tuần. Mình thường chấm điểm attack surface bằng các yếu tố này:

```
Exposure
+ Complexity
+ Trust boundary crossing
+ Parser/normalizer involved
+ Async/background processing
+ Privileged consumer
+ Historical patch churn
+ Feature rarely audited
+ Default enabled
+ Works unauth or low-priv
```

Điểm càng cao, càng đáng đào.

Ví dụ surface hấp dẫn:

- unauthenticated import/upload
- low-priv user tạo workflow/report/template
- webhook receiver
- file conversion service
- admin feature reachable qua indirect path
- plugin/theme/package installation
- backup restore
- SSO/SAML/OAuth parsing
- reverse proxy + backend routing
- queue/worker architecture
- multi-tenant isolation
- old legacy endpoint vẫn bật mặc định

Surface kém hấp dẫn hơn:

- cần full admin
- feature disabled by default
- chỉ chạy local CLI
- impact chỉ self-XSS/self-DoS
- không có crossing sang privileged component

---

## 5. Approach thực tế: đi từ bản đồ hệ thống đến giả thuyết

### Bước 1: Vẽ kiến trúc trước khi đọc bug

Tạo bản đồ:

```
Client
  ↓
Reverse proxy / gateway
  ↓
Auth middleware
  ↓
Router / controller
  ↓
Service layer
  ↓
Database / storage / cache
  ↓
Queue
  ↓
Worker
  ↓
Filesystem / network / plugin / template / command / interpreter
```

Sau đó đánh dấu:

- Chỗ nào nhận input từ user?
- Chỗ nào enforce auth?
- Chỗ nào normalize dữ liệu?
- Chỗ nào lưu dữ liệu?
- Chỗ nào đọc lại dữ liệu?
- Chỗ nào chạy với quyền cao hơn?
- Chỗ nào gọi external/internal network?
- Chỗ nào load file/module/template/config?

Rất nhiều người chỉ audit request path. Researcher giỏi audit cả **post-request lifecycle**.

---

### Bước 2: Tìm trust boundary

Các boundary quan trọng:

```
unauth → authenticated
low-priv → admin
tenant A → tenant B
external → internal
frontend → backend
API server → worker
data → code
config → execution
file → module
URL → internal request
metadata → control flow
```

Mỗi boundary đặt câu hỏi:

> “Có đường vòng nào đi qua boundary mà không đi qua guard chính không?”
> 

Ví dụ khái niệm:

- API endpoint có auth check, nhưng worker task cùng chức năng thì không.
- UI không cho set field nguy hiểm, nhưng API/import cho set.
- Admin action không gọi trực tiếp được, nhưng webhook/job có thể trigger.
- Upload path không executable, nhưng backup restore đưa file sang vùng khác.
- Tenant isolation check ở controller, nhưng background job query thiếu tenant filter.

---

### Bước 3: Tìm invariant bảo mật

Invariant là luật “không bao giờ được sai”.

Ví dụ:

```
User upload must never become executable code.
Low-priv user must never create admin-executed task.
External request must never reach internal admin service.
Tenant-controlled data must never affect another tenant.
Untrusted input must never select class/type/module.
Validated URL must be the same URL later requested.
```

Sau đó brainstorm cách phá invariant:

- Có parse nhiều lần không?
- Có encode/decode nhiều lần không?
- Có normalize khác nhau giữa OS/framework/proxy không?
- Có async path bỏ qua validation không?
- Có import/export làm mất metadata bảo mật không?
- Có cache key collision không?
- Có race giữa check và use không?
- Có fallback/default dangerous không?
- Có legacy compatibility path không?
- Có feature flag/mode khác làm guard biến mất không?

Top researcher thường tìm bug bằng cách **phá luật**, không phải bằng cách tìm function nguy hiểm.

---

## 6. Kỹ thuật brainstorm: “What happens later?”

Đây là câu hỏi cực mạnh.

Khi thấy user có thể tạo thứ gì đó, đừng dừng lại ở request hiện tại.

Hỏi:

> “Thứ này sẽ được ai dùng sau đó?”
> 

Ví dụ:

```
User creates file
→ thumbnailer reads it
→ indexer extracts metadata
→ antivirus scans it
→ converter transforms it
→ search engine indexes it
→ backup packs it
→ restore unpacks it
→ worker processes it
→ admin views it
→ template engine renders it
→ plugin loader scans it
```

Mỗi “later consumer” là một attack surface mới.

Nhiều RCE nằm ở consumer phụ, không nằm ở upload endpoint.

Đặc biệt chú ý:

- thumbnail generation
- PDF/image/video conversion
- document preview
- archive extraction
- search indexing
- syntax highlighting
- markdown rendering
- antivirus integration
- webhook dispatch
- email notification
- report generation
- audit log rendering
- backup/restore
- scheduled jobs

---

## 7. Kỹ thuật brainstorm: “Data becomes control”

Một dấu hiệu cực đáng đào là khi dữ liệu user ảnh hưởng đến control flow.

Các câu hỏi:

```
User có chọn được class/type không?
User có chọn được template name không?
User có chọn được route/action không?
User có chọn được provider/driver/backend không?
User có chọn được protocol không?
User có chọn được file extension không?
User có chọn được parser mode không?
User có chọn được job name không?
User có chọn được config key không?
User có chọn được environment/profile không?
```

Khi data biến thành control, bug có thể nâng cấp rất nhanh.

Ví dụ tư duy:

```
filename → path selection
extension → parser selection
content-type → handler selection
job_type → worker function selection
template_name → template loading
provider → backend driver
url_scheme → protocol behavior
```

Sink-source truyền thống hay bỏ qua chỗ này vì chưa có “dangerous sink” rõ ràng. Nhưng researcher nhìn thấy đây là nơi dữ liệu đang **điều khiển hệ thống**.

---

## 8. Kỹ thuật brainstorm: “Ai nghĩ ai đã validate?”

Một pattern rất hay gặp:

```
Component B trusts Component A validated it.
Component A assumes Component B will validate it.
Result: nobody validates it.
```

Câu hỏi:

- Controller validate chưa?
- Service layer có validate lại không?
- Worker có tin DB là sạch không?
- Import path có dùng cùng validation với UI không?
- API v1/v2 có cùng policy không?
- Mobile API có khác web API không?
- GraphQL resolver có bypass REST middleware không?
- Admin UI có gọi endpoint internal mà user thường cũng gọi được không?
- CLI/import/migration có bypass policy không?

RCE chain hay bắt đầu từ “validation chỉ tồn tại trên happy path”.

---

## 9. Kỹ thuật brainstorm: “Môi trường nào làm assumption sai?”

Một bug có thể không tồn tại trong dev mode nhưng tồn tại trong production-like deployment, hoặc ngược lại.

Brainstorm theo môi trường:

```
Linux vs Windows path
case-sensitive vs case-insensitive filesystem
single-node vs cluster
direct app vs behind proxy
HTTP/1.1 vs HTTP/2
container vs bare metal
cloud metadata available vs unavailable
debug mode vs production mode
enterprise SSO enabled vs local auth
plugin enabled vs disabled
multi-tenant vs single-tenant
```

Các mismatch hay nguy hiểm:

- proxy normalize path khác backend
- filesystem normalize tên file khác app
- URL parser của validator khác HTTP client
- archive library xử lý path khác OS
- framework route matching khác reverse proxy
- content-type sniffing khác extension check
- Unicode/case normalization khác database

Đây là nguồn bug “không ai thấy” vì mỗi team chỉ nhìn một layer.

---

## 10. Approach white-box: đọc code như researcher

Khi có source code, đừng đọc từ đầu đến cuối. Đọc theo lớp.

### Lớp 1: Entrypoints

Tìm:

- routes/controllers
- upload/import endpoints
- webhook endpoints
- auth middleware
- admin-only endpoints
- API versions
- GraphQL resolvers
- background job producers
- CLI/import tools
- plugin/theme/template APIs

Mục tiêu không phải tìm bug ngay, mà là lập bản đồ.

---

### Lớp 2: Security gates

Tìm các function kiểu:

```
requireAuth
requireAdmin
checkPermission
validatePath
sanitizeFilename
validateUrl
isSafeRedirect
isAllowedTemplate
isInternalRequest
tenantScope
```

Sau đó hỏi:

> “Có path nào làm cùng hành động nhưng không gọi gate này không?”
> 

Đây là variant analysis.

Nếu một endpoint update config gọi `requireAdmin`, hãy tìm mọi nơi khác cũng update config. Nếu một path validate URL, tìm mọi nơi khác cũng fetch URL.

---

### Lớp 3: Dangerous consumers

Không cần grep sink trước, nhưng vẫn nên lập inventory consumer:

```
template render
file read/write
archive extract
network fetch
dynamic import/load
reflection/class loading
deserialization
command/process execution
script engine
expression engine
SQL/query builder
LDAP/JNDI-like lookup
PDF/image conversion
```

Rồi nối ngược:

> “Consumer này nhận dữ liệu từ đâu?”
> 
> 
> “Dữ liệu đó đã từng đi qua trust boundary nào?”
> 
> “Có storage trung gian không?”
> 
> “Có path async không?”
> 
> “Có actor khác nhau giữa producer và consumer không?”
> 

Đây là source-sink nâng cấp: không chỉ trace direct input, mà trace **lifecycle**.

---

## 11. Approach black-box: model state machine

Nếu không có source, đừng chỉ fuzz parameter ngẫu nhiên. Hãy model trạng thái.

Ví dụ với một feature import:

```
create object
→ upload artifact
→ validate artifact
→ save artifact
→ process artifact
→ publish artifact
→ render artifact
→ export/backup artifact
→ delete artifact
```

Ở mỗi state hỏi:

- Có field nào chỉ set được lúc create nhưng không lúc update?
- Có validation khác nhau giữa create/update/import?
- Có object ở trạng thái half-created không?
- Có race giữa validation và processing không?
- Có retry queue dùng dữ liệu cũ không?
- Có admin review path render dữ liệu khác user path không?
- Có export/import làm mất permission metadata không?

Bug nghiêm trọng hay nằm ở transition:

```
state A safe → transition bug → state B dangerous
```

Không phải nằm ở một request đơn lẻ.

---

## 12. Approach fuzzing: fuzz nơi có grammar và boundary

Fuzzing có giá trị nhất khi target có parser hoặc state machine phức tạp.

Surface đáng fuzz:

- archive parser
- image/document metadata parser
- URL parser
- SSO/SAML parser
- template parser
- markdown/parser extensions
- import/export format
- protocol parser
- deserializer
- custom config format
- request routing/proxy parsing

Nhưng fuzzing kiểu researcher không phải “ném random input”. Nó là:

```
understand grammar
identify security invariant
generate weird but valid-ish inputs
compare parser A vs parser B
compare version old vs new
compare accepted vs processed
observe crashes + logic differences
```

Đặc biệt mạnh là **differential testing**:

```
Validator says: allowed
Processor says: interpreted differently
```

Hoặc:

```
Version A rejects
Version B accepts
```

Hoặc:

```
Library parser sees X
Application wrapper sees Y
```

Với RCE, crash không phải lúc nào cũng là mục tiêu. Logic differential nhiều khi đáng tiền hơn crash.

---

## 13. Patch diffing mindset

Researcher giỏi đọc patch không chỉ để tìm CVE cũ, mà để tìm **vùng code có lịch sử sai lầm**.

Khi thấy một patch bảo mật, hỏi:

- Fix này có đầy đủ mọi entrypoint không?
- Có cùng bug class ở feature khác không?
- Có bypass vì normalize khác không?
- Patch chặn symptom hay root cause?
- Có test case không? Test case reveal assumption gì?
- Có branch/version/plugin chưa được fix không?
- Có code copy-paste tương tự không?
- Có partial fix cho unauth path nhưng quên authenticated low-priv path không?

Một patch thường nói:

> “Team này từng hiểu sai boundary ở đây.”
> 

Đó là mỏ vàng cho variant research.

---

## 14. Tư duy chain: biến bug nhỏ thành impact lớn

Khi tìm được primitive, đừng vội kết luận severity. Hãy lập “capability graph”.

Ví dụ:

```
Can control filename
→ can influence path?
→ can write outside intended directory?
→ can place file where another component reads?
→ can choose extension?
→ can trigger reload?
→ can get privileged consumer to parse it?
```

Hoặc:

```
Can trigger internal request
→ can hit internal service?
→ can cause state change?
→ can upload/change config?
→ can trigger worker?
→ can get code-like behavior?
```

Hoặc:

```
Can create low-priv workflow
→ workflow executed by system?
→ workflow has privileged context?
→ workflow can access secrets/files/network?
→ workflow can call plugin/helper?
```

Đây là sự khác biệt lớn: researcher không chỉ hỏi “bug này là gì?”, mà hỏi:

> “Bug này cho mình capability gì? Capability đó mở cửa nào tiếp theo?”
> 

---

## 15. Brainstorm canvas dùng được ngay

Khi audit một feature, viết ra bảng này:

```
Feature:
Actor:
Required privilege:
Input controlled:
Stored where:
Consumed by:
Consumed when:
Consumed as what:
Security gate:
Trust boundary crossed:
Parser/normalizer involved:
Can affect path/type/url/template/config/job?
Possible primitive:
Possible chain:
What invariant could break:
```

Ví dụ điền ở mức trừu tượng:

```
Feature: import project
Actor: low-priv user
Input controlled: archive contents + metadata
Stored where: object storage + DB
Consumed by: background worker
Consumed as what: project config + generated preview
Trust boundary: low-priv request → privileged worker
Parser involved: archive parser + config parser
Possible primitive: path/content/control over config fields
Invariant: imported data must not affect worker execution behavior
```

Chỉ cần canvas này, bạn sẽ brainstorm sâu hơn hẳn so với grep sink.

---

## 16. Các “seams” rất đáng đào

Trong 0day RCE research, bug hay nằm ở đường nối:

```
proxy ↔ backend
auth middleware ↔ route handler
API ↔ worker
upload ↔ converter
storage ↔ template renderer
import ↔ runtime
config ↔ reload mechanism
plugin ↔ core
tenant data ↔ global cache
frontend validation ↔ backend processing
old API ↔ new permission model
database value ↔ generated code/config
```

Một câu thần chú:

> “Vulnerability lives at the seam.”
> 

Nơi hai component gặp nhau là nơi assumption lệch nhau.

---

## 17. Dấu hiệu một hướng đào có tiềm năng RCE

Khi audit, nếu thấy các dấu hiệu này, nên đào sâu:

- User kiểm soát nội dung được xử lý bởi worker.
- Worker chạy với quyền cao hơn user.
- Có import/export/backup/restore.
- Có template/expression/rule/workflow engine.
- Có plugin/theme/extension system.
- Có parser custom hoặc wrapper quanh parser.
- Có nhiều bước normalize/encode/decode.
- Có URL fetcher hoặc webhook.
- Có file write rồi later processing.
- Có cache/session/task queue dùng object phức tạp.
- Có admin preview/render dữ liệu user tạo.
- Có compatibility code cho legacy format.
- Có code comment kiểu “trusted”, “internal only”, “should be safe”, “already validated”.
- Có patch gần đây quanh validation, path, auth, parser, deserialization.

Comment kiểu “already sanitized” thường đáng đọc hơn cả sink nguy hiểm.

---

## 18. Cách nghĩ của top researcher: đào ít nhưng sâu

Người mới thường làm:

```
100 endpoints × 5 phút mỗi endpoint
```

Researcher mạnh thường làm:

```
1 subsystem × nhiều ngày
```

Họ hiểu subsystem đó đến mức biết:

- dữ liệu đi đâu sau request
- chỗ nào validate
- chỗ nào không validate
- format nội bộ là gì
- worker nào xử lý gì
- default config ra sao
- mode nào hiếm người dùng nhưng vẫn bật
- historical bug ở component đó
- cách dev team nghĩ về trust boundary

0day nghiêm trọng thường là phần thưởng cho **depth**, không phải breadth.

---

## 19. Mental model nâng cao: “weird machine”

Một hệ thống lớn luôn có những “máy ảo vô tình”:

- workflow engine
- template engine
- rule engine
- CI pipeline
- plugin loader
- query builder
- report generator
- document converter
- serializer/deserializer
- package manager
- config reloader

Chúng nhận input, có trạng thái, có instruction-like behavior, và tạo side effect.

Tư duy researcher:

> “Feature này có đang vô tình tạo một programming environment cho user không?”
> 

Nếu có, câu hỏi tiếp theo là:

> “Sandbox/capability boundary ở đâu?”
> 

RCE thường là lúc “data customization” lén trở thành “code execution”.

---

## 20. Một quy trình thực tế cho mỗi target

Dùng vòng lặp này:

```
1. Pick high-value subsystem
2. Map data lifecycle
3. Identify trust boundaries
4. Write security invariants
5. Find places where data becomes control
6. Search for parser/normalizer mismatch
7. Look for async/high-privileged consumers
8. Extract small primitive
9. Build capability graph
10. Try to chain to meaningful impact in lab
11. Generalize to variants
12. Write minimal, responsible report
```

Điểm quan trọng: **primitive trước, RCE sau**.

Đừng ép bản thân tìm RCE ngay. Hãy tìm:

- file write
- path control
- URL control
- template control
- type control
- config control
- task control
- route confusion
- auth context confusion
- tenant confusion

Rồi hỏi: “primitive này đi tiếp được không?”

---

## 21. Sự khác biệt cuối cùng

Sink-source hunting:

```
Có input không?
Có sink không?
Có filter không?
Bypass filter được không?
```

0day RCE research:

```
Hệ thống có assumption gì?
Boundary nào quan trọng nhất?
Dữ liệu đổi nghĩa ở đâu?
Ai consume dữ liệu sau đó?
Consumer có privilege cao hơn không?
Có primitive nào sinh ra không?
Primitive có chain được không?
Patch/variant nào reveal bug class không?
```

Một câu tóm gọn:

> **Bug hunter tìm đoạn code sai. Researcher tìm mô hình tin tưởng sai.**
> 

Và một câu cực thực dụng:

> **Muốn tìm RCE, hãy tìm nơi data đi qua nhiều layer, được lưu lại, rồi được một component privileged diễn giải lại thành control.**
>