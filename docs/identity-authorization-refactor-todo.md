# Identity 权限体系重构 TODO

状态：完整重构进行中；S0 仅保留为历史验证证据，当前按 exact Action = same-key Permission 模型直接切换，不保留兼容层

更新日期：2026-09-02

关联设计：[identity-authorization-refactor.md](identity-authorization-refactor.md)

模块接入流程：[module-authorization-onboarding-sop.md](module-authorization-onboarding-sop.md)

## 0. 执行约束

- [x] 本文档作为本次权限重构的唯一开发清单；每完成一项，连同代码、测试和验收证据一起勾选。
- [x] 不使用 Domainry Builder，不创建 `.domainry` 开发任务，不运行 Builder 的 model/apply/verify 流程。
- [x] 不使用 worktree；直接在当前 Identity、Runtime、SDK 仓库按批次修改。
- [x] 任何数据库只有一个宿主拥有的 `_schema_migrations`；Identity 嵌入模块只通过宿主 migration registrar 提交 source-owned migration。
- [x] Identity 的持久化 DDL/DML 优先使用 `github.com/domainry/domainry-orm`；ORM 无等价能力时，必须在代码旁写明原因并补齐 SQLite、MySQL、PostgreSQL 方言测试。
- [x] 可集合化的数据库写入必须批量执行并遵守方言参数上限；允许在内存中组装批次，不允许按记录逐条发 DDL/DML。
- [x] 严格按第 10 节依赖顺序开发；同一编号下的存储与 registry 子阶段允许交叉，但没有上游验收证据不得接入启动链路。代码未上线，不新增历史兼容、alias 或双轨逻辑。
- [x] 不把本次重构扩大成认证、目录、组织、审计、访问评审或整个角色版本模型的重写。
- [x] S0 standalone 纵向切片已经完成并留下证据；当前继续执行第 3-9 节完整重构，不能再以 S0 作为缩小最终验收范围的理由。

### 0.1 今天讨论结论的覆盖索引

| 今天确认的问题 | 本文档中的最终落点 |
| --- | --- |
| Runtime 里的接口是否都校验权限 | 所有入口必须解析为一个注册 Action。角色授权 Action 只校验同 key Permission；匿名、已登录本人、服务身份和运维入口走各自显式非角色策略，见 1.2、B1、B2、D2 |
| module 贡献的 surface 是否校验 | module surface 必须贡献 stable Action；角色授权路由只声明一个同 key Permission，不保留 `AllPermissions`/`AnyPermissions`，host 与 module 领域边界都校验，见 B4 及模块 SOP |
| 管理端是不是同一套实体增删改查逻辑 | 是。Identity 管理资源也建立 create/read/update/delete 和独立业务命令 Action；当前粗粒度 `*.write` 直接删除，不做历史迁移，见 1.3、B2 |
| URL 能不能限定权限 | URL 是 HTTP Action binding，不是 Permission 主键；method+path 必须解析到稳定 Action，再由 Action 声明权限，见 1.1、B1 |
| 内置 URL 是否属于 Action 集合 | 属于。Identity、Runtime 内置路由，auth/SDK/ops/probe，以及 module 路由都进入完整入口清单，见 1.2、B2、D2 |
| URL/页面 Action 目录放在哪里 | Action、Method/URL、页面 binding 和授权策略属于代码/元数据/module source manifest 与运行时 ActionRegistry，不新增 Action 表；配置 API 从 registry 投影这些信息，见 1.1、B1、F2 |
| 功能权限如何初始化到 DB | 启动、workspace provisioning、metadata activation 都从代码/元数据 Action 的 owned PermissionDefinitions 幂等同步 `_identity_permissions`，见 A3、A4、D2 |
| 元数据对象是否自动有默认权限 | 每个成功激活的 ObjectSchema 必须声明能力集并生成其支持的默认 Action/Permission；不能因 `system_object` 直接跳过，见 B3 |
| 角色怎么选择权限 | 只从 DB 中 active+enabled 的 PermissionDefinition 选择，仍写入版本化 `RoleSchema.Permissions`；同步权限不会自动给普通角色授权，见 A5 |
| `_identity_authorization_catalogs` 能不能删 | 能，但必须先拆出 PermissionDefinition 和 Application registration、切断 AccessBundle 依赖，再在 Batch E 删除，见 C、E |
| `_identity_permission_usages` 是否多余 | 不新增；usage 来自运行中的 ActionRegistry 投影，见 1.1、F2 |
| `_identity_permission_resources` 和元数据对象是否重复 | 是，所以不新增；ObjectSchema 仍由 Runtime/元数据拥有，`resource_key` 只是 Permission 展示分组，见 2.1、D2 |
| Permission 发布页要不要版本 | 不要。PermissionDefinition 是 current reconciled configuration；只有 RoleSchema 继续走正常版本配置，见 1.1、F2 |
| 是否为了少表牺牲职责 | 不以最少表为目标；只避免重复 authority。最终新增 permissions 和 applications 两个职责明确的 current-state 表，删除两张 catalog 表，见 2 |
| 角色配置的人应该看到什么 | 页面展示“能力/页面操作 + HTTP Method/URL”，不要求用户理解对象、FunctionGrant、DataPolicy；保存时编译为 RoleSchema permission keys 和既有数据/字段策略，见 1.1、F2 |
| 新接入 Notification 这类 module 怎么初始化 | module 只维护一份 source-owned Action manifest；host 在 ready 前校验 Action、同步 owned Permissions 并挂载，完整步骤与验收门槛见模块 SOP |
| 客服属于自己的部门但要查看销售组织客户 | `OrgID` 保持真实所属组织；用户可选 `support_org_id` 派生额外有效组织树。角色只授予客户查询 Action，并以 `target_org` 数据范围限定 `owner_org_id IN support_org_scope_ids`；数据策略不包含 read/write 功能 grant，见 1.1、12.26 |
| 附件里四表/Catalog V2/version 方案是否采用 | 不采用。吸收“Method+URL 面向用户、module 与内置 Action 统一声明、启动 reconcile Permission、角色正常配置、运行时快照缓存”部分；Action 本身不落库，也不引入 usage/bundle/revision 表，不建设 Catalog V2，见 2.3 |
| 是否使用 Builder 开发 | 不使用，见 0 |

### 0.2 当前第一阶段：先跑通 Identity standalone 权限管理闭环

第一阶段的目标不是一次完成 Runtime、SDK、module 和三种部署形态，而是先用现有 `cmd/identity-server` 与 `frontend/identity-admin` 验证最终用户能否理解并正确配置这套接口模型。

只做这一条纵向链路：

```text
Identity 内置接口 Action 声明
  -> 启动时生成 owned PermissionDefinitions
  -> reconcile 到 standalone Identity DB 的 _identity_permissions
  -> GET /identity/permissions 返回 DB Permission + 当前 Identity Action/URL 投影
  -> Identity Admin 按“功能 / 操作 / Method+URL”展示
  -> 角色直接发布现有 RoleSchema 的新版本（schema-hash CAS、幂等、审计）
  -> Identity 自己的管理接口按该角色 Permission 返回 2xx/403
```

第一阶段范围：

- [x] 只选择 Identity 自有的角色管理、功能权限管理两组管理接口作为代表切片；先把 list/get、现有 authoring/validate/publish 或写操作的真实 route matrix 梳理正确，不先改完整个平台 vocabulary。
- [x] 定义最小 Action 声明字段：stable ActionKey、capability/operation/label、Method+router template、可选管理页面、authorization strategy、required/owned Permission 和现有 governance。
- [x] Action 声明只在代码和 Identity 进程内 registry；不新增 Action 表。
- [x] 实现 `_identity_permissions` current storage 与 standalone 启动 reconcile，只接入本切片 owned permissions。
- [x] `GET /identity/permissions` 以 DB PermissionDefinition 为配置真相，并从当前 Identity ActionRegistry 临时投影 Method/URL/page usages；usage 不落库。
- [x] 复用现有 `frontend/identity-admin` 角色页，把功能权限区域改成面向用户的 capability/operation 视图，底层 key 只作为高级详情；通过 Identity-native `PUT /identity/roles/{roleID}/permissions` 直接发布新的 RoleSchema 版本。
- [x] 使用现有 Vite `/api -> http://127.0.0.1:8081` 代理连接 standalone Identity；不为原型另造 mock backend 或 Runtime 中转层。
- [x] S0 曾临时保留旧 AuthorizationCatalog 以验证页面；该阶段已经结束，最终实现直接删除 Catalog，不保留 compatibility adapter。
- [x] S0 曾延后 Runtime/module/Catalog 切换；该阶段已经结束，这些工作现已进入当前完整重构范围。

第一阶段只保留最小验证：

- [x] standalone Identity 能启动，Identity Admin 能登录并读取真实 `/identity/permissions`。
- [x] 空数据库启动后，本切片 Permission 自动出现；重复启动不重复；数据库能看到 current rows。
- [x] 角色页面能按“角色管理/功能权限管理 -> 操作 -> Method+URL”勾选并通过现有 RoleSchema 版本流程保存/发布；真实页面发布产生版本 `2`、新 schema hash 和审计事件。
- [x] 使用两个测试角色验证一个允许、一个拒绝的 Identity 管理接口，结果分别为成功和 403。
- [x] 重启后 PermissionDefinition 和角色配置仍存在；同一 SQLite 重启后 RoleSchema 仍为版本 `2`、hash 不变，API 回读已移除的权限仍未恢复。
- [x] 后端切片测试、前端相关单测和前端 build 通过。

本切片验证通过后，先让用户确认页面信息架构、Action/Permission 粒度、接口 DTO 和配置流程，再进入完整 Batch B、其它 Identity 管理资源以及 module SOP；首轮不以全仓 `go test ./...`、三方言、所有授权策略或所有 module E2E 作为阻塞条件。

## 1. 已确定的最终模型

后续实现不得再并行引入另一套权限概念。唯一链路是：

```text
代码/元数据的一份 source-owned Action manifest
  -> ActionDefinition.AuthorizationStrategy + role Action 的同 key Permission + URL/页面 bindings
  -> 启动或元数据激活时同步 owned PermissionDefinitions 到 _identity_permissions
  -> ActionRegistry 投影 URL/页面配置树，Identity 从 DB 加载 Permission current snapshot
  -> 管理员按“能力/页面操作/URL”勾选，并为每个 grant 选择 data_scope，系统写入 RoleSchema.Permissions[] 和既有 field policy
  -> Identity 解析用户角色并生成 AccessBundle
  -> 路由/调用解析 stable action_key，Action 所属边界执行功能权限校验
  -> Runtime 对数据/字段/引用/导出策略继续做对象级校验
```

### 1.1 固定决策

- URL 只作为 HTTP Action 的 binding，不作为 Permission 主键。
- Action 是可执行、可校验的操作；内置 Identity URL、Runtime URL、元数据 Action、module surface，以及匿名/self/service/ops/非 HTTP 入口，都必须进入完整运行时 ActionRegistry。
- 代码/元数据/module manifest 是 Action 安全定义的唯一 authority；Identity 不新增 `_identity_actions`，也不允许管理员在数据库中改 method/path、required permissions、risk 等代码安全语义。
- ActionDefinition 必须覆盖 HTTP Method + 注册路由模板、面向管理员的具体 URL/页面 binding、capability/operation、授权策略和 required permission keys。非 HTTP Action 使用其它 binding kind，不得伪造 URL。
- Action key 是稳定主键，URL 改动不导致角色授权失效；同一个用户可理解操作可由多条 endpoint Action 组成，配置 UI 按 `capability_key + operation_key` 聚合。
- Permission 是角色可选择的能力键。每个角色授权 Action 定义且只定义一个同 key Permission；不允许 Permission 复用、all/any 权限列表、alias 或动态 permission callback。
- 每个 active PermissionDefinition 必须来自一个代码/元数据 canonical owner 的 owned Action definition；角色引用、前端菜单和历史数据库数据都不能成为定义源，也不存在保留的 workspace-wide 管理员 Permission。
- role-authorized Action 与它的同 key Permission 由同一个 canonical owner 定义；anonymous/authenticated/self/delegated/service/ops Action 不创建角色 Permission。
- 每个 Permission 只有一个 canonical owner；不同 owner 定义同一个 key 时，即使字段暂时相同也拒绝装配，避免以后产生双重 authority。
- PermissionDefinition 是 current configuration，不做发布版本，不新增 permission revision/publication 页面。`definition_hash` 和同步 snapshot hash 只用于幂等与并发控制，不是业务版本。
- RoleSchema 的 `Permissions []RolePermission` 是角色 grant 的唯一真相；每项同时保存 exact `permission_key`、该 grant 自己的 `data_scope` 和可选 `audit_denial`，不新增 role-permission 中间表。
- 不存在角色级 `DataPermissions`。同一对象的 read/update/delete 等 Permission 可以分别使用不同 data scope；Identity 只在生成 AccessBundle 时把这些 grant 编译为按 exact action 区分的执行策略。
- `IdentityUser.OrgID` 始终是真实所属组织；可选 `support_org_id` 只提供额外支持目标。它派生的 active subtree 通过可信 `support_org_scope_ids` subject fact 供通用 `target_org` scope 使用。
- 权限同步只增加“可选择项”，绝不自动授予普通角色；默认/系统角色的授权只来自当前明确 seed 中的 RoleSchema。
- Action 与 Permission/URL/页面的绑定由当前 ActionRegistry 实时投影；不新增 `_identity_permission_usages`，也不再把 `ActionUsages` 塞进持久化 PermissionDefinition。
- Runtime ObjectSchema 继续拥有字段、引用、facts 和对象生命周期，不新增 `_identity_permission_resources`。
- `resource_key`/`operation_key` 是 Permission 的稳定展示和分组信息，不是 Identity 对 ObjectSchema/URL 的复制 authority；完整可执行 Action key 始终是 `ActionDefinition.Key`。
- 角色配置 UI 默认不要求管理员手工拼装 `resource/action`。管理员看到“客户管理/编辑”“PATCH /objects/customer/records/{recordID}”，选择该 Permission 及其 data scope；保存时写入同一个 `RoleSchema.Permissions[]` grant。高级治理页可以展示底层 key。
- `public`/`tenant-admin`/`ops` exposure 只决定入口挂载位置，不代表已授权；授权仍由 Action 的 authorization strategy 决定。
- 不定义 workspace-wide 管理员 Permission；管理员角色也只由显式的 same-key Action Permissions 和独立的数据策略组成。
- `*`、`<resource>.*` 不作为正向功能授权。既有 deny guardrail 的 pattern 只是拒绝策略表达式，不能创造 Action 权限。
- 判定顺序固定为：Action/策略存在 -> 身份类型满足 -> role Action 的同 key Permission active+enabled -> `RoleSchema.Permissions` exact grant -> deny guardrail -> Runtime 数据/字段/引用/导出策略。
- 任意其它 Permission 都不能执行 `identity.users.list`、`customer.read` 等 Action；必须分别拥有那些 exact Permission。
- 未注册 Action、未知 Permission、已停用 Permission、已退役 Permission均 fail closed。
- 请求热路径不逐次查询数据库或解析 JSON。ActionRegistry 和数据库 Permission current snapshot 在启动/revision 变化时编译成不可变 endpoint resolver 与 required-permission map并原子替换。

### 1.2 “所有接口都受控”的准确含义

不是每条 HTTP 路由都需要数据库中的角色 Permission。每条 HTTP/RPC/job/agent/module 入口都必须进入入口清单，并显式属于以下一种授权策略；不得靠“没有 wrapper”隐式放行：

| 策略 | 典型入口 | 是否生成角色 Permission |
| --- | --- | --- |
| `anonymous` | C 端游客、login、OIDC discovery/JWKS、provider callback、health/probe | 否；必须显式声明且不能携带 policy/audience |
| `authenticated` | 登录用户；既包括仅要求登录，也包括 exact Permission 和本人/管理分支 | 可选；存在时只生成并校验 Action 同 key Permission，领域 policy 在登录后执行 |
| `signed` | webhook、schedule、SDK application token、agent/tool、Runtime reconcile 和运维调用 | 否；由对应签名 middleware 校验 policy、scope、expiry、audience 及调用绑定 |

`/objects/{objectKey}` 这类通用 router 必须先用 path 参数解析为已经注册的具体 Action（例如 `customer.read`），随后仍执行普通的 exact `role_permission` 校验；它不是独立的 dynamic permission 策略。

功能权限的最终执行点是 Action 所属边界：Identity 自有 Action 在 Identity 校验，Runtime 自有 Action 在 Runtime 校验，module Action 由 host 做公共门禁且 module application service 保留领域内最终校验。不是把 Identity 的所有接口转发给 Runtime 再校验。

### 1.3 管理端 CRUD 和语义 Action 规则

- 每个管理资源先定义稳定 resource key，再定义 `create/read/update/delete`；实际不支持的操作必须在资源能力中显式标记 unsupported，不能靠缺路由猜测。
- list/get/search/versions 等入口各自使用自己的 stable ActionKey 和同 key Permission；UI 可以把它们聚合显示，但后端授权不复用另一 Action 的 Permission。
- create/update/delete 默认使用各自同名 Permission，不再长期共用一个粗粒度 `.write`。
- disable/enable/unlock/force_logout/assign/revoke/approve/reject/export 等不是 CRUD 的命令，定义独立语义 Action 和同 key Permission，不按 HTTP method 猜。
- Identity 当前的 `identity.users.write`、`identity.roles.write`、`identity.menus.write` 等旧 broad key 直接从生产定义、seed、前端 guard 和测试中删除。代码未上线，不创建角色兼容迁移、alias evaluator 或双重 grant。
- key 命名使用稳定语义而非 URL：例如 `identity.users.list`、`identity.users.get`、`identity.users.create`、`identity.users.update`、`identity.users.delete` 都是独立 Action/Permission；特殊命令使用 `identity.users.disable` 等语义 key。
- metadata object 的默认 Action/Permission 使用 `<object_key>.<operation>`；module/平台内置能力使用 owner 自己的稳定 namespace。method/path 改动不得迫使 Permission key 改名。

### 1.4 当前代码基线（复核证据）

- `internal/domain/identity/contract/identity_platform_permissions.go` 仍手写 `IdentityPlatformPermissionKeys`，管理权限主要是 read/write 粗粒度。
- `internal/transport/http/identity/identity_routes.go` 把 method/path 与 `identityPermission(...)` 分开手写；同一文件同时存在 permission、all permissions、self-or-permission 和 authenticated-only 路由。
- `internal/domain/identity/service/identity_domain_service.go` 的 PermissionDefinition 仍是进程内 map，reload 通过 `ReplacePermissionDefinitions` 覆盖。
- `internal/application/identity/identity_permission_catalog_projection.go` 当前从角色引用反向“补出”未知 Permission；这会让 Role 变成 Permission 定义源，必须删除。
- 同一投影当前只生成对象 create/read/update/delete 并跳过 `system_object`；Runtime `runtime/bootstrap/runtime/identity_catalog.go` 却为所有对象生成 create/read/update/delete/export，二者不一致。
- Runtime 已有 `RuntimeEndpointContractV1.PermissionPolicyRef`，module 已有 `modulehttp.Route.Permission/AnyPermissions/PrincipalOnly` 和 host 级校验；重构应将这些适配到统一 registry，而不是再并行手写第三份路由权限表。
- Runtime 当前 catalog 只额外硬编码 Notification 权限词汇，未从所有 `modulehttp.Surface` 泛化同步 PermissionDefinition。
- Notification 当前已经出现三份不一致的权限词汇：`ProductRoutes()`/surface 使用 `notification.template.*` 等 dotted Permission；Notification `Catalog()` 和 application service 使用 `notification_template.read/draft/...` 等 resource/action；Runtime `identity_catalog.go` 又手写一份 Notification catalog。module SOP 必须把三份收敛到一个 source-owned Action manifest。
- Identity `internal/assembly/module/factory.go` 当前把 management routes 贡献成 `Authenticated + PrincipalOnly` surface，丢失了 `GET /identity/roles -> identity.roles.read` 这类真实 route permission；因此 host 只能知道“已登录”，不能发现完整内置 Action/URL 目录。
- `identity_admin_routes.go` 还单独维护 `/admin/org/roles -> identity.roles.read` 等管理页面映射；页面、路由 gate 和 Permission 目录必须改由同一 Action source manifest 投影。
- Identity server 还包含 auth、browser gateway、Remote SDK、audit module、portability ops、health 和直接注册的 tenant-admin 路由；完整覆盖测试不能只扫描 `identity_routes.go`。
- Identity 的 `registerAuditRoutes` 基线虽然读取 Audit `modulehttp.Surface`，实际却统一包成一个聚合管理员 gate，没有按 route 自己的 Permission 执行；这是 module surface 统一改造必须覆盖的现存偏差。
- `principal_resolver.go`、SDK binding 和 browser application registration 仍读取/发布 AuthorizationCatalog；两张 catalog 表现在不能直接删除。

## 2. 数据表处置清单

### 2.1 新增

- [x] 新增 `_identity_permissions`，保存当前、可动态管理的 PermissionDefinition。
- [x] 新增 `_identity_applications`，单独保存应用身份、redirect URLs 和状态，不再借授权 catalog 保存应用注册信息。

`_identity_permissions` 固定字段：

| 字段 | 规则 |
| --- | --- |
| `id` | 稳定行 ID |
| `workspace_id` | workspace 隔离 |
| `permission_key` | workspace 内唯一，RoleSchema 存的就是此键 |
| `resource_key` | 管理页面分组，不是元数据资源副本 |
| `operation_key` | 展示动作片段，如 create/read/approve；完整 Action key 不在本表重复持久化 |
| `label` | 可本地化展示名的当前默认值 |
| `description` | 当前说明 |
| `category` | 管理页面分类 |
| `source_kind` | platform/object_default/business_action/builtin_surface/module_surface |
| `source_owner` | 稳定 canonical owner key，例如 `identity:builtin`、`application:<key>`、`module:<key>`；用于同步、退役和冲突判断；每个 permission_key 只能属于一个 owner |
| `definition_status` | active/retired，由代码定义同步控制 |
| `enabled` | 管理员动态开关；代码重同步不得覆盖已有值 |
| `definition_hash` | source-controlled 字段规范化后的 hash |
| `source_snapshot_hash` | 本 owner 最近成功同步的完整集合 hash，用于 compare-and-swap、防止旧同步覆盖新激活；不是发布版本 |
| `created_at` | 创建时间 |
| `updated_at` | 最后定义或管理变更时间 |

唯一约束：`(workspace_id, permission_key)`。

`source_owner` 是定义 authority，不是 Action usage。一个 owner 每次提交自己拥有的完整 PermissionDefinition snapshot；本次缺失且原本属于该 owner 的 key 才会 retired。只引用这些 Permission 的其他应用/Action 不参与 retire。reconcile 请求必须带 `previous_snapshot_hash` 与新 snapshot hash，解决远程重试乱序问题，不需要额外 permission publication/revision 表。

`_identity_applications` 固定为 current registration，至少包含 `id`、`workspace_id`、`application_key`、`redirect_urls_json`、`status`、`created_at`、`updated_at`，唯一约束为 `(workspace_id, application_key)`。应用 credential secret 继续由现有配置/secret 边界管理。

### 2.2 最终删除

- [x] fresh schema 不包含 `_identity_authorization_catalogs`。
- [x] fresh schema 不包含 `_identity_authorization_catalog_revisions`。
- [x] 删除两张表对应的 store、repository、schema ownership、portability spec、index 和 API 测试；代码未上线，不保留历史 migration 测试。
- [x] 删除 Runtime catalog publisher、SDK catalog publish/resolve 合约及 Identity catalog JSON 热路径。

删除采用 fresh schema 直接切换：应用 redirect 只写 `_identity_applications`，Runtime/SDK 使用新合约，AccessBundle 不读取 catalog；不实现历史回填、drop migration 或兼容 adapter。

### 2.3 明确不新增

- [x] 不新增 `_identity_permission_usages`。
- [x] 不新增 `_identity_permission_resources`。
- [x] 不新增 `_identity_role_permission_assignments`。
- [x] 不新增 permission bundle/member 表；现有 permission set/group 已经承担权限组合职责。
- [x] 不新增 Action/Permission catalog/version/revision/publication 表，不建设 Catalog V2。
- [x] 不新增 `_identity_actions`；URL、页面 binding、required permissions 和安全策略属于代码/元数据/module ActionRegistry。

### 2.4 原样保留并继续使用

- [x] `_identity_role_definitions` / `_identity_role_definition_versions`：保留 RoleSchema 版本和 `Permissions []string`。
- [x] `_identity_roles` / `_identity_user_role_assignments` / role requests：保留运行态角色和人员分配。
- [x] permission set、permission set group、deny guardrail：保留组合与拒绝策略。
- [x] data/field/reference/export policy：保留细粒度策略；最终在 Runtime 当前 ObjectSchema 上执行。
- [x] users、organization units、menus、credentials、MFA、sessions、external accounts、events、access reviews：不因本次重构改变表职责；人员与汇报事实直接属于 user。

## 3. Batch A：PermissionDefinition 存储与接入

目标：先提供 current PermissionDefinition 的正式存储/reconcile 能力；A0-A3 不改变现有 Action/catalog 对外合约。启动接入 A4-A6 必须等待 B1-B2 的 canonical Action source 完成，禁止把现有“角色引用反向补 Permission”的投影固化进新表。

### A0. 基线与保护测试

- [x] 固化现有 Identity 平台权限 key 清单、元数据对象 CRUD 投影和业务 Action `RequiresPermission` 投影；这些测试记录旧行为但不把旧 read/write 粒度或 system_object 跳过规则当成目标。
- [x] 固化 RoleSchema `Permissions []string` 的保存、校验、版本发布和角色授权行为。
- [x] 固化 permission set/group、deny guardrail 与 ops credential 的当前优先级，并证明它们不能生成其它 Action grant。
- [x] 固化 Identity 全入口清单：identity management、auth/browser、Remote SDK、audit surface、portability ops、health、直接注册 tenant-admin 路由；真实 registrar 汇总为 155 个排序后 pattern，并锁定 baseline hash。
- [x] 固化 Runtime 的 `EndpointContracts`、business ActionCatalog、`modulehttp.Surface` 路由清单及当前 host module permission gate。
- [x] 固化 embedded module 使用宿主 DB、transaction、dialect、migration lock 和 `_schema_migrations` 的测试。
- [x] 标注当前 catalog 依赖测试为 compatibility，避免误认为最终设计。

A0 compatibility-only baseline 包括 `internal/adapter/identitysdk/binding_test.go`、`internal/assembly/core_test.go`、`module/factory_test.go` 和 `internal/transport/http/server/remote_sdk_contract_test.go` 中的 `AuthorizationCatalog` 发布/读取断言；这些测试只保护 Batch C/E 前的过渡行为，不代表 catalog 是最终授权真相。

### A1. Schema 和迁移

- [x] 在 Identity owned schema 中定义 `_identity_permissions` 全部字段、唯一约束和必要索引。
- [x] 添加 `(workspace_id, permission_key)` 唯一索引。
- [x] 添加 `(workspace_id, definition_status, enabled)` 查询索引。
- [x] 添加 `(workspace_id, source_owner)` 同步索引。
- [x] 将表加入 schema ownership 和 portability specs。
- [x] Standalone 模式通过 Identity 自有 migration registrar 建表。
- [x] Embedded 模式只提交 source-owned migration 给宿主 registrar，不创建第二本 migration ledger；借用模式不增加 relation prefix，直接使用宿主 schema 中的原始表名。
- [x] 增加 SQLite、MySQL、PostgreSQL schema rendering/contract 测试；表、唯一约束和两个索引使用同一组声明渲染。

### A2. Domain 和 Repository 合约

- [x] 扩展 PermissionDefinition，使持久化字段与当前展示/Action 元数据字段职责明确；`ActionUsages` 只存在于 API view projection，不进入 persistence record。
- [x] 新增独立的 `IdentityPermissionDefinitionRepository`，不强迫所有既有 `IdentityRepository` 测试桩一次性实现新方法。
- [x] 定义按 workspace 列出 current PermissionDefinitions 的接口。
- [x] 定义按 `source_owner` 提交完整 snapshot 的 reconcile 接口，包含 `previous_snapshot_hash`、新 snapshot hash 和 receipt。
- [x] 定义管理员 enable/disable 所需接口，但实际管理 API 放到 Batch F 开放；接口只允许改变 active definition 的 current `enabled` state，missing/retired/幂等请求不写入。
- [x] 定义并测试 canonical definition hash；hash 不包含 `enabled`、数据库 ID 和时间戳。
- [x] 定义并测试 canonical source snapshot hash；输入排序无关，相同集合重复同步 hash 相同。
- [x] 把现有 `IdentityPermissionDefinition` 中 risk/approval/assurance/ActionUsages 等 Action 属性移出持久化模型；API 兼容投影与持久化 entity 分开。

### A3. ORM 持久化实现

- [x] 使用 domainry-orm 实现 workspace-scoped list/get、current enablement update，以及 reconcile 内按方言参数上限分批的多行 upsert。
- [x] reconcile 新定义时插入 `active + enabled=true`。
- [x] reconcile 已有定义时更新 source-controlled 字段，但保留管理员设置的 `enabled`。
- [x] 同一个 `source_owner` 中本轮缺失的 key 标记为 `retired`，不物理删除。
- [x] 已退役 key 被同 owner 重新定义时恢复为 `active`，继续保留原 `enabled` 决策。
- [x] 不同 canonical owner 抢占同一 `permission_key` 时返回明确冲突错误并回滚整个事务。
- [x] `previous_snapshot_hash` 不匹配时拒绝 stale reconcile，旧 Runtime/重试请求不得覆盖更新后的定义集合。
- [x] 只引用现有 Permission 的 Action 不写 Permission 行，也不会因自己的 snapshot 缺失而 retire 别人的 Permission。
- [x] 所有读写都使用 request/assembly 传入的 transaction executor，不绕过宿主事务边界；无宿主 executor 时才由 standalone store 创建并提交本地事务。
- [x] 覆盖 workspace 隔离、幂等、退役、恢复、owner 冲突、stale snapshot、引用不夺权、enabled 保留和事务回滚测试。

### A4. 启动和元数据激活同步

- [x] 代码 Action contract 同时表达 required permission references 与本 owner 的 PermissionDefinitions；先合并完整 ActionRegistry，再只提取 owned definitions 同步。
- [x] Identity standalone 启动时同步完整 Identity built-in 权限；已删除 `generatedGlobalPermissionKeys`、平台硬编码列表和角色反向拼定义逻辑。
- [x] workspace provisioning 时同步 Identity built-in 权限，保证新 workspace 不需要先访问权限页才初始化。
- [x] Runtime 启动/metadata activation 时同步项目 Object、business Action、Runtime built-in 与 module owner 的权限；embedded 走 host transaction，remote 走 SDK service credential。
- [x] 代码未上线，不实现第一次升级回填；fresh workspace 只从当前代码/元数据 Action owned definitions 初始化 `_identity_permissions`。
- [x] 删除“从 RoleSchema 中发现未知 key 就生成 PermissionDefinition”的投影文件与调用；角色只能引用定义，永远不能反向创造定义。
- [x] 角色中存在、但当前代码无法识别的 key 标记 unknown，不静默删除、不授权，并为后续人工修复生成治理结果。
- [x] Identity metadata reload observer 改为可返回 error，并将流程调整为“候选 snapshot -> Action/Permission 校验与 reconcile -> 原子替换 runtime snapshot”；失败继续使用旧 snapshot，不得先 Apply 再报错。
- [x] 数据库 active/enabled PermissionDefinitions 加载为不可变内存快照；内存只做缓存，不再是定义真相。
- [x] restart 后从数据库恢复管理员 `enabled` 状态，代码同步不得把它重置。
- [x] 同步成功记录 source owner、snapshot hash、增加/更新/retire 数量与 request ID 的结构化日志证据，不创建业务发布版本；embedded 日志明确只表示 applied，最终 commit 仍归宿主。

### A5. 读取和角色校验切换

- [x] `GET /identity/permissions` 改读当前 workspace 数据库定义，并返回 active/disabled/retired 状态。
- [x] 普通角色新增/修改只能选择存在、active、enabled 的 permission key；发布服务统一调用数据库快照校验。
- [x] 已经被角色引用的 disabled/retired key 继续可查询并带状态，不能再新增选择。
- [x] permission set/group 已删除功能 `Permissions` 字段，只组合 data/field/reference/export 非功能策略，因此不存在可绕过 RoleSchema 的功能 permission key；deny guardrail 继续使用独立 deny 表达式。
- [x] principal 构建时直接从 `RoleSchema.Permissions` 汇总，并用同一数据库快照过滤 unknown/disabled/retired key 后再执行 deny guardrail；permission set/group 不再增加功能权限。
- [x] 现有角色校验、effective access、governance report 使用同一个 PermissionDefinition snapshot。
- [x] AuthorizationRevision 的计算输入加入实际生效的 PermissionDefinition snapshot/state fingerprint；不必先增加全局 revision 表，但 disabled/retired 变化必须让新 principal/bundle revision 改变。
- [x] 保持当前前端 `permissionsApi.catalog` 返回结构的兼容字段，新增状态字段采用向后兼容方式。

### A6. Batch A 退出条件

- [x] 权限行在系统启动后自动出现于数据库，无需手工 seed SQL。
- [x] 对同一份代码/元数据重复启动不产生重复行。
- [x] 管理员停用状态能够跨重启和同 owner 重同步保留。
- [x] 删除代码定义后，权限变为 retired 而不是消失或被物理删除；同 owner 恢复时重新 active 且保留 enabled 决策。
- [x] built-in Identity 权限、对象默认权限、业务 Action 权限均能被角色正常选择。
- [x] 权限同步只产生可选 Permission；reconcile 不写 RoleSchema，也不会给普通角色自动授权。
- [x] 角色中的 unknown/disabled/retired 权限不会进入新 AccessBundle；permission set/group 不再包含或增加功能权限。
- [x] Identity 单元测试、数据库测试、assembly 测试全部通过。

## 4. Batch B：统一 ActionDefinition 和内置 URL 校验

目标：消除“路由表一份、权限包装器一份、Permission 生成又一份”的重复定义。

### B1. Action 合约

- [x] 在 `domainry-foundation` 的 deployment-neutral shared contract 层定义规范化 `ActionDefinition`/authorization strategy；Identity 不能依赖 Runtime，Identity SDK 只承载 reconcile/application wire contract，不能为 Runtime、Identity、module 各建一个不兼容模型。
- [x] `ActionDefinition` 固定包含 stable key、owner、source kind、capability/operation/label、exposure、authorization strategy、HTTP/页面/非 HTTP bindings、可选同 key Permission、risk/assurance/approval/idempotency/audit/lifecycle。
- [x] authorization strategy 只支持 anonymous protocol、authenticated principal、self-or-exact-permission、delegated credential、service identity、exact role permission 和 operations identity；删除 static all/any 与 dynamic permission resolver。
- [x] role-authorized Action 与它拥有的 Permission 必须 key/owner 完全相同；exceptional Action 不拥有 Permission，不存在 reference/reuse 模式。
- [x] 定义 `ActionRegistry`：注册、冻结、按 action key 和 method/path 解析、重复冲突检查、同 key Permission owner 校验和 usage 反向投影。
- [x] 适配而不是重复定义现有资产：Runtime `ActionSchema`、`RuntimeEndpointContractV1`、Foundation `modulehttp.Route`、Identity route definitions 都投影到同一个规范化 registry；`modulehttp.Route.AllPermissions/AnyPermissions` 已删除。
- [x] Runtime endpoint contract 当前由 generator 生成；Action 接入必须修改 source/generator 和 contract tests，禁止直接手改生成文件形成第四份 authority。
- [x] HTTP route 只保存 method/path binding；非 HTTP Action 可没有 URL。
- [x] role-authorized Action key 与 Permission key 强制相同；一个 Permission 只对应这一个 Action。
- [x] Action manifest 只存在于代码/元数据和冻结后的运行时 registry；不得把 handler/function pointer 或 Action 安全定义复制进 Identity 持久化模型。
- [x] 一个 HTTP Action 必须含 method + router template；配置树显示具体 `display_route_template`，不能把原始动态 `/objects/{objectKey}` wildcard 暴露成可授权项。
- [x] registry 在服务 ready 前冻结，运行中只读。
- [x] 普通 HTTP handler 不再自行解释 permission string；公共 middleware 必须先从已编译 snapshot 解析 Action，再执行声明的 authorization strategy。

### B2. Identity 内置 surface 改造

- [x] 生成并评审 Identity 完整 route/action matrix，覆盖 `identity_routes.go`、`auth_routes.go`、browser gateway、Remote SDK、audit module routes、portability ops、health/probes、server 直接注册路由和未来 module surfaces。
- [x] Identity authoring capability 中的 `ConfigurationRoutes`、`ValidationEndpoint`、`Execution.PermissionModel` 也必须由/校验到同一 matrix，不能让 capability contract 继续维护另一份 URL/permission truth。
- [x] matrix 每行固定记录 owner、method/path、action key、authorization strategy、同 key Permission（如适用）、exposure 和 audit/governance；不允许只有 URL 没有策略。
- [x] matrix 同时记录 capability/operation/label 和 `/admin/...` 页面 binding；`identity_admin_routes.go`、菜单可见性和后端 route gate 都从 matrix 投影。
- [x] 为 users、organization units、roles、role assignments、role requests、menus、role menus、permissions、data scopes、field permissions、security、access reviews、governance 等管理资源定义 CRUD/语义 Actions。
- [x] list/get/search/versions 分别使用独立的 read-effect exact Action；create/update/delete 分离；disable/enable/unlock/force_logout/assign/revoke/approve/reject 等使用独立语义 Action。
- [x] 盘点现有 `Authenticated(...)` 管理路由，逐条明确是 principal-only、self、dynamic owner policy 还是遗漏 Permission；不允许把“已登录”长期当成管理授权。
- [x] 将 route 注册和 authorization middleware 绑定到同一个 ActionDefinition，禁止手写第二份 permission string。
- [x] 保留经评审的 self-or-permission 语义，将它表达成 Action policy，不在 handler 里另造授权逻辑。
- [x] Identity 内置 PermissionDefinitions 由同一 matrix 中 canonical-owned permission 定义生成并 reconcile；角色管理 list/get/create/update/delete/assign/configure 等 Action 可共享或拥有稳定 Permission，但 URL/Action 本身不落 Identity DB。
- [x] 非 HTTP 的内置管理能力同样注册 Action，不用虚构 URL。
- [x] 菜单可见性和页面 required permissions 改为从同一 ActionRegistry/route matrix 投影，删除前端菜单、后端路由各维护一份 permission mapping 的状态。
- [x] auth discovery/callback/login、Remote SDK service endpoints、portability ops 明确保留各自协议身份策略，不为它们伪造普通角色 Permission。

### B2.1 现有 broad permission 直接清理

- [x] 先生成完整 permission vocabulary 审计，识别粗粒度 key、命名不一致和语义重复，例如 `identity.permission.configure` 与 `identity.permissions.write`、`identity.audit.view` 与 Audit owner 权限；逐项确定唯一 canonical key/owner。
- [x] 为每条现有入口确定最终 exact ActionKey，并删除旧 broad key；代码未上线，不建立旧 key 映射、角色迁移或 alias evaluator。
- [x] 同步更新 admin route/menu projection、authoring capability、默认角色 seed 和前端 route guard；生产代码与 fixture 不再引用旧 broad key。
- [x] 新角色页面只展示 exact Action 权限；不存在 legacy alias 或旧 bundle 兼容分支。
- [x] 增加 list/get/create/update/delete/semantic Action 可独立授权的测试，并证明任意其它 Permission 不扩展成当前 Action。

### B3. 默认对象 Action

- [x] 提供唯一的 `DefaultActionsForObject(ObjectSchema)` 规则。
- [x] 每个成功激活的 ObjectSchema 必须有显式 capability set；普通可变对象默认生成 create/read/update/delete，存在导出 surface 时生成 export。
- [x] 只按对象声明的 immutable/read-only/no-delete/no-export 等实际能力裁剪，不生成无法调用的操作；没有能力声明时使用标准 CRUD 默认值。
- [x] `system_object` 只表示所有权，不再作为跳过权限的理由；只要它是已激活 ObjectSchema，就按其 capability set 生成 Action/Permission。
- [x] 内部 persistence table 若不是 ObjectSchema surface，不生成 Action/Permission。
- [x] 默认 Action 同时产生 stable ActionDefinition 与 owned PermissionDefinition，Permission 自动进入 DB 但不自动进入任何普通角色。
- [x] 通用 router 仍注册 `/objects/{objectKey}/records` 等模板；metadata activation 按每个 active ObjectSchema 生成具体运行时 Action，例如 customer list/get/create/update/delete；router resolver 只负责绑定 `objectKey=customer` 到该具体 Action，配置投影显示具体 URL。
- [x] 请求匹配通用 router 后提取 `objectKey` 和 operation，解析到已经注册的具体 `action_key` 后执行普通 same-key Permission 校验；角色页绝不提供“全部 objectKey”泛化授权项。
- [x] metadata candidate 的默认 Action/Permission 在激活前完成校验和 reconcile；失败不发布 ObjectSchema。
- [x] 删除 Identity 与 Runtime 现在不一致的两套 CRUD 推导逻辑。

### B4. Module surface

- [x] 严格执行 [module-authorization-onboarding-sop.md](module-authorization-onboarding-sop.md)；未通过 source manifest、reconcile 和覆盖测试的 module 不得 ready。
- [x] 以现有 `modulehttp.Surface`/`modulehttp.Route` 为落点补齐 stable Action key、capability/operation/label、页面 binding、authorization strategy 和 same-key owned Permission 声明；不支持 Permission reuse，也不另造与 modulehttp 并行的 surface 注册体系。
- [x] module 只能维护一份 source-owned Action manifest；route mounting、host gate、OpenAPI、Identity reconcile payload 和配置树都必须从它投影，禁止 module `Catalog()`、Runtime hardcode、surface Permission 三份手写。
- [x] Notification、Audit 及后续 module surface 在装配时注册自己的 Actions。
- [x] 先以 Notification 作为首个 SOP 验证：收敛 `ProductRoutes()`、旧 Catalog/internal resource-action 和 Runtime hardcode，逐项确定唯一 canonical action key 与同 key permission，并直接删除旧定义，不提供兼容迁移。
- [x] 删除 Runtime `identity_catalog.go` 中 Notification 专用权限硬编码；所有 module 都从各自 surface/action contribution 泛化派生。
- [x] 宿主合并所有 Action contributions 并校验后，再按 owner reconcile owned PermissionDefinitions；冲突或未知引用时拒绝 ready，成功 receipt 前不得挂载/激活新 surface。
- [x] module 的 permission canonical owner 保持 source module，不转移给 host/Identity。
- [x] embedded 模式由 host 在同一 DB/transaction/migration 边界装配和同步；standalone/remote module 由 owner 使用 service credential 同步，语义相同。
- [x] host 的通用 authentication/permission/governance gate 与 module application service 的领域内校验都保留，避免 transport gate 成为唯一防线。
- [x] module 后续升级/卸载必须保留 stable action key；当前未上线代码中的旧 key 直接删除，URL 改动只更新 binding，不引入 alias 或双重 grant。

### B5. 覆盖与退出条件

- [x] 增加测试：每条受保护 Identity route 恰好映射一个 ActionDefinition。
- [x] 增加测试：所有 Identity route 都有且只有一个显式 authorization strategy；受保护 route 未注册、策略缺失、引用未知/disabled/retired Permission 时装配或请求失败。
- [x] 增加测试：public route 必须显式标记 public，不能因漏注册而放行。
- [x] 增加测试：module-contributed surface 一定经过同一校验。
- [x] 增加测试：self、service credential、通用对象 router 的具体 Action 解析、ops identity 不会被错误地折叠成普通角色权限。
- [x] 删除已被 registry 替代的散落权限常量/路由 permission wrapper，确有非路由用途的常量必须标明 owner。

## 5. Batch C：应用注册拆分和 Catalog 直接删除

### C1. `_identity_applications`

- [x] 定义 application key、workspace、redirect URLs、status、created/updated timestamps，并落实 `(workspace_id, application_key)` 唯一约束。
- [x] 使用 domainry-orm 实现 application registration repository。
- [x] redirect URL 校验和 application existence 检查改读 `_identity_applications`。
- [x] service credential secret 继续留在既有 secret/config 边界，不复制到此表。
- [x] 明确不做 catalog application 历史回填：代码尚未上线，fresh schema 和直接注册是唯一受支持路径。
- [x] Identity browser application 启动改为 register current application，不再发布空 AuthorizationCatalog。
- [x] AuthHandler 的 `ApplicationRegistered` 判断改读 application repository，不再用 `Catalog().CurrentRevision()` 判断应用是否存在。

### C2. Catalog 直接切断

- [x] 明确不实现 Catalog compatibility adapter、`compat:*` owner、旧 receipt 或双写路径。
- [x] 新 AccessBundle 解析不再要求 catalog 已发布。
- [x] 删除 principal resolver 中的 `identity.catalog_not_published` 硬依赖。
- [x] 删除 catalog 对 grants、data/field/reference/export policy 的二次裁剪。
- [x] 删除 workspace-wide 管理员 Permission；每个角色授权 Action 只接受 exact same-key Permission。

### C3. 退出条件

- [x] Identity 在没有 catalog JSON 的情况下可完成登录、角色解析和 AccessBundle 生成。
- [x] redirect 校验完全依赖 `_identity_applications`。
- [x] 生产代码中不存在 Catalog Publish/Get/Revision 入口或兼容调用。
- [x] 请求授权热路径不读取 catalog JSON。

## 6. Batch D：SDK 与 Runtime 切换

### D1. SDK 合约

- [x] 增加按 workspace + source owner 提交完整 PermissionDefinition snapshot 的批量 reconcile 合约，包含 previous/new snapshot hash、definition counts 和 receipt。
- [x] 增加 application registration 合约。
- [x] 增加 authorization revision / snapshot 合约，替换 CatalogRevision 语义。
- [x] local binding 与 remote HTTP binding 行为、错误码和事务语义一致。
- [x] 未知 owner、定义冲突、stale activation receipt 返回可定位错误。
- [x] remote reconcile 使用 application service credential，并校验 workspace/application/source owner scope；普通用户 token 不能发布代码权限定义。
- [x] reconcile API 管定义，角色配置 API 管授权选择，两者严格分开。

### D2. Runtime ActionRegistry

- [x] Runtime 从 Object 默认 Actions、authored business Actions、`EndpointContracts`、内置 Runtime surface 和 `modulehttp.Surface` contributions 构建唯一规范化 registry。
- [x] 通用对象路由必须由 path 中的 object/action 解析到 registry 内已存在的具体 Action，再执行普通 same-key Permission 校验；不存在 dynamic permission resolver。
- [x] anonymous、service protocol、principal-only、ops 路由必须按 1.2 显式分类，不为追求“每路由一 Permission”制造错误权限。
- [x] Runtime 启动时先校验 registry，再调用 Identity reconcile，收到成功 receipt 后才 ready。
- [x] 元数据更新采用“构建候选 registry -> reconcile -> 原子激活”顺序，失败继续使用旧 snapshot。
- [x] Runtime 直接用当前 ObjectSchema 校验 data/field/reference/export policy，不再要求 Identity 镜像资源细节。
- [x] Identity 对 data/field/reference/export 配置做结构和 permission-key 校验；Runtime 在候选 metadata/schema 上做对象、字段、关系存在性及执行语义的最终校验。
- [x] 管理端资源/字段选择数据来自 Runtime 当前 metadata API，不从 `_identity_permissions.resource_key` 反建 ObjectSchema。
- [x] 请求按 resolved Action.AuthorizationStrategy 执行校验；角色授权分支检查 required permissions 与 AccessBundle，不存在 Action 或 required Permission 时 fail closed。
- [x] URL、RPC、job/agent 等不同入口使用同一 Action 语义。

### D3. revision 与缓存

- [x] Identity 的 AuthorizationRevision 覆盖 user/organization/roles/role assignments/permission sets/guardrails，以及过滤后的 active+enabled Permission state fingerprint；可以沿用当前确定性 hash，不为此强制新增 revision 表。
- [x] Runtime 维护 Metadata/ActionRegistry revision。
- [x] AccessBundle/cache key 使用 subject/workspace + AuthorizationRevision；需要对象结构时再组合 MetadataRevision。
- [x] 不在每个请求中查 `_identity_permissions`，也不解析 catalog JSON。
- [x] 权限停用后，新解析 principal/bundle revision 必须变化；Runtime 对已有缓存按 revision/最大陈旧窗口失效，不能让旧自包含权限无限有效。
- [x] 明确 bearer/session/worker reauthorization 的最大陈旧窗口和强制刷新路径，测试 disabled Permission 在窗口内收敛。

### D4. 跨部署验收

- [x] embedded direct binding 端到端测试通过。
- [x] remote SDK + real Identity HTTP server 合同测试通过。
- [x] Runtime 内置 surface、Identity 内置 surface、metadata Action、module surface 均有授权正反例。
- [x] anonymous、authenticated principal、self-or-exact-permission、delegated credential、service identity、operations identity、ordinary exact role permission 每种策略都有正反例和越权回归测试。
- [x] SQLite、MySQL、PostgreSQL 关键 schema/repository 合同通过。

## 7. Batch E：彻底删除 Authorization Catalog

- [x] 代码未上线，fresh schema 直接初始化 PermissionDefinition 和 Application；不做 workspace 回填或升级检查。
- [x] 删除 Identity Catalog Publish/Get/Resolve API 和 handler。
- [x] 删除 SDK catalog DTO、client、local/remote binding。
- [x] 删除 Runtime `identity_catalog.go` publisher 和 catalog assembly dependency。
- [x] 删除 Runtime catalog 中资源 fields/references/facts 镜像以及 Notification 专用拼装。
- [x] 删除 `internal/infrastructure/persistence/database/identitycatalog`。
- [x] 删除 principal resolver、binding、catalog policy 中所有 catalog 读取、展开和过滤代码。
- [x] fresh schema、indexes、ownership、portability specs 中不存在 `_identity_authorization_catalogs` / `_identity_authorization_catalog_revisions`。
- [x] 代码未上线，不提交 drop migration 或已有数据升级测试。
- [x] 删除只验证旧 catalog 行为的测试，保留登录、角色解析、AccessBundle、application registration 和 Permission reconcile 新链路回归测试。
- [x] 全仓 `rg` 确认生产代码不再出现 CatalogRevision、authorization catalog store 或 catalog-not-published。

## 8. Batch F：动态管理与治理闭环

### F1. Permission 管理 API

- [x] 增加 exact Action `identity.permissions.set_enabled` 和 enable/disable API，只能改管理员控制字段，不改 source-owned 定义字段。
- [x] 增加 `identity_permission_enablement_changed` 审计事件，记录 actor/workspace/request 上下文以及 permission key、before/after、reason。
- [x] 停用后使 AuthorizationRevision 的 Permission state fingerprint 变化，并使新解析的 AccessBundle 立即移除该能力。
- [x] role Action 先检查 same-key Permission current state，再检查 exact RoleSchema grant；不存在 workspace-wide 管理员 grant，ops/service 路径按独立策略处理。
- [x] 不建立 wildcard、最后管理员或特殊角色语义；只保护 `identity.permissions.set_enabled` 自身不可被停用，角色管理恢复能力由各 exact Action 和部署恢复流程承担。
- [x] retired Permission 不允许直接 enable；必须由 canonical owner 恢复定义后再启用。

### F2. 管理端页面

- [x] 权限页直接展示数据库 current definitions，不做 permission 发布版本页。
- [x] 按 resource/category/source 分组，显示 active/disabled/retired 和 canonical owner。
- [x] 页面以“能力 + 操作 + Method/URL/页面绑定”解释权限；URL 只来自 live registry projection，不是可编辑 Permission key。
- [x] 角色页只允许勾选 active+enabled；已引用异常 key 保留状态并不可新增选择。
- [x] Action usage 通过 Action owner 的 registry query 实时展示：embedded 可直接聚合，remote 从 Runtime/module 查询；Identity 不落 usage 表，owner 不可达时明确显示 unavailable。
- [x] 对象资源文案来自 Runtime/ObjectSchema 投影，不在 Identity 维护资源元数据副本。
- [x] 角色权限编辑继续提交正常 RoleSchema version/change path；Permission 页面没有 draft/publish/version lifecycle。
- [x] 前端 route guard/menu visibility 只是体验投影，数据来自同一 registry/permission API；最终授权始终以后端 owner boundary 为准。

### F3. 治理

- [x] 报表列出仍被角色引用的 disabled/retired/unknown permission keys。
- [x] effective-access explain 能说明 Permission 来源、角色来源、deny guardrail 和最终结果。
- [x] access review 能看到权限状态变化，但不把 PermissionDefinition 变成版本发布实体。

## 9. 全局验收矩阵

### 功能完整性

- [x] Identity、Runtime、module 的所有入口都在各自 owner/host 边界解析到一个显式 Action authorization strategy；不存在“漏 wrapper 就放行”的入口。
- [x] 所有角色功能权限 Action 都检查 DB 中 current PermissionDefinition；匿名、本人、service、ops 等入口按声明的非角色策略校验，不能混为一谈。
- [x] module 贡献的 surface 与内置 surface 使用同一注册、同步和校验机制。
- [x] 每个成功激活的元数据 ObjectSchema 都按 capability set 初始化默认 Action 和对应 Permission，`system_object` 不再被直接跳过。
- [x] Identity 角色管理等内置 URL 对应的 Action/Permission 会自动初始化到 DB 并可供角色选择。
- [x] Identity 管理资源能独立配置 read/create/update/delete 和必要语义 Action；现有 broad write 权限从生产定义、seed、前端和测试中直接删除。
- [x] 当前平台 permission vocabulary 中语义重复/owner 冲突的 key 已完成 canonicalization；旧 key 直接删除，不做等价迁移或 retirement 兼容。
- [x] 管理员能动态停用 Permission，重启后状态保持，授权立即按 revision 收敛。

### 数据一致性

- [x] 一个 workspace 的同一 permission key 只有一行和一个 canonical owner。
- [x] reconcile 重复执行、进程重启、metadata reload 都幂等。
- [x] stale reconcile 被 CAS snapshot hash 拒绝；只引用 Permission 的 Action 不会取得 owner 或 retire 定义。
- [x] 角色选择只存于 RoleSchema，不出现第二份 role-permission authority。
- [x] retired/disabled/unknown key 不会被静默授权。
- [x] RoleSchema 中出现的未知 key 不会反向创建 PermissionDefinition。
- [x] Runtime ObjectSchema 不复制到 Identity 资源表。

### 工程与部署

- [x] 本次授权重构新增或修改的 DML 使用 domainry-orm；跨表复制、结构迁移等 ORM 无等价能力的既有 raw SQL 不属于本重构验收，并继续要求本地原因和方言测试。
- [x] embedded module 与 standalone SaaS 行为一致。
- [x] 每个数据库仍只有宿主的 `_schema_migrations`。
- [x] migration、portability、backup/restore 覆盖新表并清理旧表。
- [x] route/action coverage 测试覆盖 Identity 全部 route registrars、Runtime EndpointContracts 和所有 modulehttp surfaces。
- [x] Identity、SDK、Runtime 全量测试和 lint 通过。

## 10. 开发顺序与提交边界

严格按以下顺序执行，每一项可以形成独立、可回滚的提交：

1. [x] S0：完成 0.2 的 Identity standalone 纵向切片；该历史顺序门已在用户明确要求继续完成权限改造后解除，最终实现和验收已覆盖全量 UI、Action 声明、`/identity/permissions` DTO、Runtime 与 module。
2. [x] A0-A3：将 S0 已验证的 `_identity_permissions` schema、repository、snapshot-CAS reconcile 补齐为正式基础和必要数据库测试。
3. [x] B1：把 S0 Action 声明提炼为 shared normalized Action contract/registry，并为现有 Runtime EndpointContract、modulehttp.Route、metadata ActionSchema 设计无损 adapter。
4. [x] B2-B2.1：从 S0 两组接口扩大到 Identity 全 route/action matrix、内置 Action 注册、CRUD/语义 Permission 定义及 broad-key 直接删除测试。
5. [x] A4-A6：完成全量 Identity 启动/workspace provisioning 同步、DB 读取、principal 过滤、RoleSchema/permission-set 校验和 assembly 测试。
6. [x] B3-B5：统一 Object 默认 Action、module contribution、菜单投影和全入口覆盖测试；已执行 module SOP 和 Notification 样例。
7. [x] C1：application registration 表、browser registration 和 redirect/application lookup 切换；未上线，不做回填。
8. [x] C2-C3：catalog 退出 AccessBundle 热路径并直接删除，不保留 compatibility adapter。
9. [x] D1：SDK local/remote reconcile、application、authorization snapshot 新合约。
10. [x] D2-D4：Runtime 完整 registry、候选激活协议、revision/cache 和跨部署测试。
11. [x] E：从代码与 fresh schema 直接删除 catalog API、代码和两张 catalog 表。
12. [x] F：Permission 开关、完整管理端页面、审计和治理闭环。

## 11. 首个开发任务

在用户确认本文档后，只开始 S0，不提前碰 Runtime、SDK/module 推广、Catalog 删除或完整 vocabulary 迁移：

- [x] 生成角色管理和功能权限管理两组实际接口的 route/action 对照并完成全量扩展；最终粒度由 same-key Action/Permission、live usage DTO 和覆盖测试锁定，证据见 12.12、12.16、12.20。
- [x] 为 `_identity_permissions` 增加满足 standalone S0 的 owned schema、必要 index 和 SQLite migration；repository 使用 domainry-orm。
- [x] 从这两组 Identity code-owned Actions 启动 reconcile PermissionDefinitions，禁止从 RoleSchema 反向补定义。
- [x] 调整 `/identity/permissions` DTO：Permission 状态来自 DB，Action/Method/URL/page usage 来自当前进程 registry，usage 不持久化。
- [x] 调整 Identity Admin 角色权限区域，按能力/操作展示接口；编辑时保留首次读取的 RoleSchema hash，使用 CAS 直接发布新版本，业务原因和幂等键进入审计/发布链。
- [x] 启动 `cmd/identity-server` 和 `frontend/identity-admin`，完成 0.2 的人工/自动验证并记录可复核的界面/API/DB 证据。
- [x] 该历史流程门已由用户后续“继续完成 TODO/收口全部问题”的明确要求解除；全部 Identity routes 已完成覆盖，证据见 12.12 与本轮最终验收。

S0 明确不新增 `_identity_actions`，不删除或升级 AuthorizationCatalog，不新增 `_identity_applications`，不接 Notification，不修改 Runtime catalog publisher，不要求 MySQL/PostgreSQL 或全仓测试先阻塞界面验证。

## 12. 执行证据（2026-09-01 至 2026-09-02）

12.1 至 12.5 保留 S0 当时的阶段性快照，用于追溯开发顺序；后续条目记录逐批替换结果，12.25 是当前最终状态。阶段性数量、临时 key 和 UI 锁定描述不应被解释为当前契约。

### 12.1 已完成实现与代码证据

- Action 单一来源：`internal/application/identity/identity_builtin_authorization_actions.go` 声明 12 条真实路由 Action、2 个 capability、4 个兼容 PermissionDefinition；`internal/application/identity/identity_action_registry.go` 在装配时拒绝重复 Action、重复 canonical owner、重复 Method+route 和未知 Permission 引用。
- A0 保护基线：Identity 平台 permission vocabulary 有顺序固定的 golden test；对象 CRUD/system-object 旧投影、business Action `RequiresPermission`、RoleSchema 发布与授权、permission set/group、deny guardrail 与 exact ops 权限均由现有行为测试锁定。它们是迁移前证据，不把旧粒度认定为目标设计。
- 全入口基线：standalone server 的现有 registrar 在挂载真实 mux 时同步记录 pattern，Browser Gateway 仍读取 SDK `RoutePatterns`；最终 inventory 覆盖 155 条 Identity/Auth/Browser/Remote SDK/Audit/portability/probe/direct routes，排序集合 SHA-256 为 `d29a20849b76e890e868f69d627c4946f50672ff641db9516c3a9190b1f66d99`。
- Runtime A0 基线：Runtime 既有 compiled EndpointContracts 和 business ActionCatalog 测试继续通过；新增 `runtime/transport/http/module_http_routes_test.go` 锁定 anonymous/principal-only 与 exact Permission 的允许/拒绝，并证明任意其它 grant 不会隐式越权为 module exact permission。
- embedded A0 基线：借用 store 的 SQLite/MySQL/PostgreSQL renderer 都保持空 relation prefix、使用宿主方言 placeholder/表名与 `_schema_migrations`；module factory 必须经宿主 registrar 执行 schema callback且不会关闭 pool，workspace provisioning/reconcile/enablement 均有 host transaction rollback 证据。
- current 存储：`internal/infrastructure/persistence/database/schema/identity_permissions.go` 使用 domainry-orm schema builder 定义 `_identity_permissions`、workspace 内 permission key 唯一约束、状态索引和 source owner 索引；表已加入 ownership、portability spec 和 `006_identity_authorization_permissions` migration。
- 批量 DML：`internal/infrastructure/persistence/database/identity/authorization/permission/store.go` 先以一条集合 UPDATE 标记 owner 旧集合，再按数据库 bind parameter 上限执行多行 UPSERT；只在内存中组装批次，不按 permission 逐条写 DB。冲突更新明确不覆盖 `enabled`、`id`、`created_at`。
- 事务所有权：reconcile 优先复用 request context 中的 host executor，不在 embedded/host 事务内另开或提交事务；只有 standalone 无 executor 时才拥有本地事务。集成测试分别证明 host rollback 后零行、host commit 后整批可见。
- 管理状态端口：独立 PermissionDefinition repository 提供 workspace-scoped `Get` 与 `SetEnabled`；后者只更新 active row 的 `enabled/updated_at`，不改 definition hash、snapshot hash、owner 或 lifecycle，并复用 host executor。集成测试覆盖 missing、跨 workspace、retired、幂等和 host rollback。
- 引用与 ownership：跨 owner 的 reference-only Action 在合并 registry 后没有 owned definition；真实 reconcile 后数据库仍只有 canonical owner 的 active 行，consumer 的空 snapshot 不写行也不 retire 别人的定义。
- reconcile 语义：同 owner 完整 snapshot 使用 previous/new snapshot hash 做 CAS；首次插入 active+enabled，缺失项 retired，恢复项 active，跨 owner 冲突整事务回滚，管理员 `enabled` 决策在同步与重启后保留。
- 热路径：`internal/application/identity/identity_permission_catalog.go` 在 reconcile 后把 DB active/enabled 状态原子替换为不可变内存快照；Action gate 先检查 Permission current state，再检查角色 grant，不逐请求查 DB，unknown/disabled/retired fail closed。
- standalone 接线：`internal/transport/http/server/service.go` 只在 standalone `NewWithStore` ready 前执行 Identity built-in reconcile；deployment-neutral core 只装配 registry/service，embedded 路径未擅自执行 remote/module 推广。
- embedded 数据库边界：`OpenBorrowedContext` 只借用宿主 pool/schema，不执行独立 migration、不增加 `domainry_identity_` relation prefix；`Factory.OpenWithDatabase` / `OpenBootstrapWithDatabase` 强制要求宿主 migration registrar，并把 Identity source-owned schema 回调提交给 registrar。借用模式中的物理表仍为 `_identity_users` 等原始表名。
- 读取投影：`GET /identity/permissions` 从 `_identity_permissions` 读取 current definition/state/hash/owner，并由当前进程 registry 投影 capability、operation、Action、Method、router template 和 page；没有 usage 表。
- 管理端：`frontend/identity-admin/src/features/org/permission-capability-view.ts` 以 `capability_key + operation_key` 聚合；`roles.tsx` 默认展示功能、操作、Method+URL 和页面入口，技术 permission key 收进详情，retired/disabled 不可选择。
- RoleSchema 发布：最终由 `internal/application/identity/identity_role_definition_publication.go` 统一编排角色增改删、带 data scope 的 Permission grants 和字段权限；`internal/application/metadata/metadata_identity_role_definition_application_service.go` 复用 `_identity_role_definitions` / `_identity_role_definition_versions`、schema-hash CAS、幂等重放、审计、角色目录同事务投影和 metadata reload。没有新增草稿、审批状态机或 role-permission 表。
- 并发边界：角色页首次 GET 保留 `X-Resource-Hash`，PUT 原样提交这份 expected hash；编辑期间若别人已发布，后端返回 409，不会在保存前重新 GET 新 hash 后覆盖并发修改。
- 收敛边界：旧 `Permissions []string + DataPermissions` 输入已停止接受；Runtime、SDK、Identity 与管理端统一使用 `Permissions []RolePermission`。permission set/group、guardrail 与 field policy 仍不能创造功能 grant。

### 12.2 待用户评审的 Action、DTO 与发布契约

S0 当前只有以下 12 条 Action；表中五个字段由 `StandaloneIdentityAuthorizationSliceActions` 同一份声明生成，测试锁定完整映射，不允许只改路由或中间件中的一份字符串。

| Capability / 页面 | Operation | ActionKey | Method + router template | Permission |
| --- | --- | --- | --- | --- |
| 角色管理 `/admin/org/roles` | 查看 | `identity.roles.list` | `GET /identity/roles` | `identity.roles.read` |
| 角色管理 `/admin/org/roles` | 查看 | `identity.roles.search` | `GET /identity/roles/search` | `identity.roles.read` |
| 角色管理 `/admin/org/roles` | 查看 | `identity.roles.get` | `GET /identity/roles/{roleID}` | `identity.roles.read` |
| 角色管理 `/admin/org/roles` | 查看 | `identity.roles.governance_detail` | `GET /identity/roles/{roleID}/governance-detail` | `identity.roles.read` |
| 角色管理 `/admin/org/roles` | 查看 | `identity.roles.versions` | `GET /identity/roles/{roleID}/versions` | `identity.roles.read` |
| 角色管理 `/admin/org/roles` | 查看 | `identity.roles.impact_preview` | `POST /identity/roles/{roleID}/impact-preview` | `identity.roles.read` |
| 角色管理 `/admin/org/roles` | 配置 | `identity.roles.validate_governance` | `POST /identity/governance/validate` | `identity.roles.write` |
| 角色管理 `/admin/org/roles` | 配置 | `identity.roles.validate` | `POST /identity/roles/{roleID}/validate` | `identity.roles.write` |
| 功能权限管理 `/admin/org/roles` | 查看 | `identity.permissions.list` | `GET /identity/permissions` | `identity.permissions.read` |
| 功能权限管理 `/admin/org/roles` | 查看 | `identity.role_permissions.list` | `GET /identity/roles/{roleID}/permissions` | `identity.permissions.read` |
| 功能权限管理 `/admin/org/roles` | 配置 | `identity.role_permissions.validate` | `POST /identity/roles/{roleID}/permissions/validate` | `identity.permissions.write` |
| 功能权限管理 `/admin/org/roles` | 配置 | `identity.role_permissions.publish` | `PUT /identity/roles/{roleID}/permissions` | `identity.permissions.write` |

`GET /identity/permissions` 的兼容 DTO 明确分三层，避免把动态状态、代码入口和历史展示字段混成同一份持久化模型：

| 字段职责 | 字段 | authority |
| --- | --- | --- |
| Permission current definition/state | `key`、`label`、`resource`、`action`、`category`、`description`、`definition_status`、`enabled`、`source_kind`、`source_owner`、`definition_hash`、`source_snapshot_hash` | `_identity_permissions` |
| 当前进程 Action usage | `action_usages[].action_key`、capability/operation、authorization strategy、Method、router/display template、page、risk/approval/assurance/lifecycle | 冻结后的 Identity ActionRegistry，实时投影，不入库 |
| S0 兼容摘要 | `source_type`、`source_action_key`、`object_key`、`action_label`、authorization/risk/approval/assurance/lifecycle 顶层字段 | 第一条 live usage 的兼容投影；Batch A2 拆成独立 API view model |

角色功能权限直接发布契约：

| 请求 | 并发与幂等 | 结果 |
| --- | --- | --- |
| `GET /identity/roles/{roleID}/permissions` | 无写入 | body 为当前 assignments；`X-Resource-Hash` 与 `X-Schema-Version` 标识 RoleSchema 当前版本 |
| `PUT /identity/roles/{roleID}/permissions`，body=`permission_keys` + `business_reason` | 必须提交编辑开始时读取的 `Expected-Schema-Hash` 和稳定的 `Idempotency-Key` | 直接产生 RoleSchema 新版本；200 返回新 assignments/hash/version；精确重放不重复写版本和审计；stale hash 返回 409 |

本轮需要用户确认的是 capability/operation 文案、S0 暂用四个 broad read/write Permission 的粒度，以及兼容 DTO 是否足够理解。URL 只是 Action usage 的说明信息，不是 Permission identity，也不可编辑。

### 12.3 自动测试证据

- `go test ./...`：通过；包含 Action route/owner 校验、SQLite reconcile/restart、角色允许/拒绝 HTTP 切片、schema/migration/portability/assembly 回归。
- `go test ./module ./internal/assembly/module ./internal/infrastructure/persistence/database`：通过；借用数据库测试断言 Identity 使用 `_identity_users`、不存在任何 `domainry_identity_%` 表、宿主 registrar 收到唯一 Identity migration，数据库中只有一本 `_schema_migrations`。
- Runtime `go test ./runtime/transport/http ./runtime/application/action ./pkg/runtimehost` 与 `go vet ./runtime/transport/http ./pkg/runtimehost`：通过；覆盖 EndpointContracts、ActionCatalog、module surface mounting 和 host permission gate。
- `go vet ./...`：通过。
- `go test ./internal/infrastructure/persistence/database/identity/authorization/permission`：通过；SQLite、MySQL、PostgreSQL 均验证一次多行 UPSERT，且冲突部分不更新 `enabled`/`created_at`。
- `go test ./internal/infrastructure/persistence/database/identity/integrationtest`：通过；覆盖首次插入、重复幂等、retire、restore、stale CAS、owner 冲突回滚、workspace 隔离、disabled 状态重启保持，以及复用 host transaction 的 rollback/commit 边界。
- `npm run test:unit`（`frontend/identity-admin`）：29 个测试文件、104 个测试全部通过。
- `npm run build`（`frontend/identity-admin`）：类型检查、品牌检查、12 条前端 route registry 检查和 Vite production build 全部通过；只有既存的大 chunk 提示，不是构建失败。

### 12.4 真实 standalone/API/DB/界面证据

- 使用临时 SQLite 启动 `cmd/identity-server`，日志显示 development listener ready；再用 Vite `/api` proxy 启动 `frontend/identity-admin`。
- 真实管理员登录成功；首次临时密码交接后重新登录进入 `/admin`，再进入 `/admin/org/roles`。
- 真实 `GET /identity/permissions` 返回 4 条 DB definition：`identity.roles.read/write`、`identity.permissions.read/write`；全部 owner=`identity:builtin`、status=`active`，live route usage 数分别为 6、2、2、2。
- SQLite 查询结果：`_identity_permissions` 行数 4、distinct permission key 数 4；唯一 migration ledger 为 `_schema_migrations`，当前 schema version 为 `006_identity_authorization_permissions`。
- 同一数据库停止并重启 standalone 后仍为 4 行，没有重复；集成测试另外证明管理员 disabled 决策不会被启动 reconcile 重置。
- 真实角色页显示“角色管理 / 功能权限管理 -> 查看 / 配置 -> Method + URL -> 页面入口”；内置 Admin 锁定，非内置 Organization administrator 可勾选，技术 key 仅在“技术详情”中显示。
- 真实页面取消 Organization administrator 的 `identity.permissions.read` 后填写业务原因并发布成功；SQLite 中 RoleSchema 从 `0.1.0` 变为 `2`，version rows 从 1 变为 2，审计事件为 `identity_role_permissions.published`，业务原因为“S0 真实页面发布验证”。
- 使用同一数据库重启 standalone，真实 API 回读 `200`、`X-Schema-Version: 2`、schema hash=`84607c0153675b2151bb13be6fc207bdfbfa1f656bdedcad41216b3c27547325`；24 个保留权限中 `identity.permissions.read` 仍不存在、`identity.permissions.write` 仍存在。
- server HTTP 切片以 Admin 角色读取 `/identity/permissions` 得到 200；改用没有 `identity.permissions.read` 的 System administrator 配置重新登录后得到 403。

### 12.5 RoleSchema 直接发布边界

- standalone 使用 `GET /identity/roles/{roleID}/permissions` 返回当前配置与 `X-Resource-Hash` / `X-Schema-Version`；`PUT` 要求 `Expected-Schema-Hash`、`Idempotency-Key` 和 `business_reason`，直接产生正常 RoleSchema 新版本。
- 发布只替换 `RoleSchema.Permissions`（其中包含每个 grant 的 data scope）；集成测试逐字段证明 RiskLevel、Audience、AssignmentMode、GrantableRoleKeys 以及 field/reference/export、permission-set、guardrail 等其它字段保持不变。
- 新增选择必须来自当前 DB active+enabled PermissionDefinition；历史已引用但当前切片尚未接管的 key 可以原样保留，避免 S0 四权限目录把既有角色权限静默删掉。unknown/retired/disabled key 不能成为新 grant。
- 精确重放返回同一版本/hash，不新增 version/audit；stale expected hash 返回 409；业务审计和角色目录投影与版本写入共用 metadata repository 事务。
- 未新增 `_identity_role_permission_assignments`、草稿/审批表或 Permission 版本表；角色功能权限唯一 authority 仍是 `_identity_role_definitions.payload_json` 中的 `RoleSchema.Permissions`。

### 12.6 B1 shared Action contract 证据

- 单一规范模型：`domainry-foundation/action` 定义 deployment-neutral `ActionDefinition`、ordinary exact Permission 与六种 exceptional identity strategy、source-owned `PermissionDefinition` 和批量原子注册后冻结的 `Registry`；该包不依赖 Identity、Runtime、HTTP handler 或数据库，也不存在 Permission reuse/reference/alias。
- fail-closed registry：stable Action/Permission/owner key 只接受规范化小写格式；Action/Permission key 或 owner 不同、重复 Action/HTTP/non-HTTP binding、retired Permission 等均在注册/冻结时失败；retired Action 不可按 key/HTTP/non-HTTP 解析。
- exact 授权：role Action 的 Permission key/owner 与 Action 完全相同；通用 router 先解析具体 Action，再执行同一 exact gate，不存在 resolver 返回任意 permission 列表的入口。
- Identity 没有第二份 Action 结构：`internal/domain/identity/model/identity_action_definition.go` 仅 alias shared contract；`IdentityActionRegistry` 先注册并冻结完整 shared registry，再投影 Identity DB record 和实时 usage。
- Runtime metadata adapter：`runtime/domain/action/projection/action_authorization_contract_projection.go` 把现有 `ActionSchema` 投影为无伪造 URL 的 non-HTTP Action；普通 Action 只拥有同 key Permission，并保留 risk、assurance、maker-checker/workflow approval、idempotency 和 audit event。
- Runtime endpoint adapter：`runtime/domain/endpoint/model/endpoint_action_adapter.go` 把 generated `RuntimeEndpointContractV1` 投影为 stable Action；角色入口生成同 key Permission，service protocol 保留 exact audience，通用 object router 不生成可被角色选择的泛化 wildcard Permission。
- generator authority：Plane 的 `runtime-surface-inventory-v1.json` 是 endpoint Action key 输入；`scripts/contracts/generate_runtime_surface_policy.py` 生成 Runtime contract 并由新单测锁定 stable derivation/重复冲突，临时重新生成结果与 `endpoint_route_policy.go` 字节一致。
- module adapter：`modulehttp.Route` 只保存一个 canonical `ActionDefinition`；HTTP pattern、exposure、authorization、Permission 和 governance 均从 Action 投影，旧 `AllPermissions/AnyPermissions`、principal flag 和 governance 副本已删除。Runtime registry 测试证明 module route 接管后旧 endpoint 描述不会同时存活。
- 验证命令：Foundation `go test ./... -run '^$'`、Runtime `go test ./... -run '^$'`、Identity `go test ./... -run '^$'` 通过；Runtime `go test ./runtime/bootstrap/runtime -run 'TestRuntimeAuthorizationRegistry' -count=1` 通过；全授权相关仓库的 Go 源码扫描无 `AllOf`、`AnyOf`、`AuthorizationFixed`、`AuthorizationDynamic`、`static_permissions_all/any` 或 `dynamic_permission_resolver` 残留。
- 本轮复核发现并修复了三处容易误授权的设计：service audience 在 endpoint adapter 中不得丢失；旧 module route 不得把 service policy 降级成 principal-only；deprecated metadata Action 的 owned Permission 保持 active，只有 retired Action 才 retire Permission。

B1 的合约/adapter 项与服务 ready 前冻结现已完成；Identity 全 route cutover 证据见 12.12，Runtime registry、公共 middleware 与候选原子激活证据见 12.14。S0 共 6 个最小验收项已全部通过；开发顺序第 1 项和用户评审项在该阶段仍保持未勾选，后由用户继续开发/最终收口指令解除，最终状态见 12.24。

### 12.7 A4 workspace provisioning 与 DB snapshot 证据

- workspace provisioning 复用冻结后的 Identity ActionRegistry，按目标 `workspace_id` 创建短生命周期 catalog coordinator，并在宿主传入的同一个 `*sql.Tx` context 中批量 reconcile `identity:builtin` owned PermissionDefinitions；没有 workspace 全局变量、第二张权限表或模块 migration ledger。
- bootstrap binding 只完成 source-owned schema 和 ActionRegistry 装配，打开时仍保持零 tenant 数据；首次 `ProvisionWorkspaceIdentity` 才在宿主事务中共同写入用户、角色、角色分配、4 条 built-in PermissionDefinition 和凭据。因此新 workspace 不需要访问权限管理 API 才初始化。
- `module/workspace_provisioning_test.go` 同时覆盖 bootstrap 和正常 embedded binding：rollback workspace 的 `_identity_permissions` 为 0，commit workspace 为 4；在 user/role/assignment/credential 四个失败边界逐一回滚后，权限行与其它 Identity 行全部为 0，clean retry 后为 4。
- workspace 初始角色和 `ReconcileWorkspaceRoles` 已从逐角色 SQL 改为 domainry-orm 多行 UPSERT，并按当前方言 bind parameter budget 分批；`authorization/role/store_batch_test.go` 在 SQLite、MySQL、PostgreSQL 上证明两个角色只生成一条双行 UPSERT，且冲突更新不覆盖 `created_at`。
- `IdentityPermissionCatalogApplicationService` 的 request path 只读取 atomic pointer 指向的 immutable `permission_key -> active/enabled` map；reconcile 完成后一次替换整个 map。管理列表每次从当前 workspace 数据库读取定义和状态，再合并 frozen registry 的 live usage，内存不是 PermissionDefinition authority。
- restart 集成测试先把 `identity.roles.get` 置为 disabled，关闭并重新打开 store/service，再执行同一代码 snapshot reconcile；receipt 为 unchanged，新的 immutable runtime snapshot 仍拒绝该权限，数据库 `enabled=false` 未被 UPSERT 重置。
- 每次 application reconcile 成功取得 receipt 后记录 `identity_permission_reconcile_applied` 结构化日志，字段包含 request/workspace、source owner、snapshot hash 与 inserted/updated/retired/unchanged；缺失 request ID 时生成 opaque ID。事件刻意命名为 `applied` 而不是 `committed`：embedded 的最终 commit/rollback 仍由 host 拥有，待 Runtime host 在提交后补最终 outcome 证据前，A4 对应全局日志项保持未勾选。
- 本项验证命令：`go test -race ./internal/infrastructure/persistence/database/identity/authorization/role ./module` 通过。A4 的 Runtime/metadata activation 两阶段协议现已补齐，见 12.14；跨 embedded/remote 的完整 Runtime 端到端验收仍保持未勾选。unknown 治理和 A5 的 permission-set/principal/revision 统一过滤见 12.11。

### 12.8 C1 application registration 证据

- `internal/infrastructure/persistence/database/schema/identity_applications.go` 使用 domainry-orm schema builder 定义 `_identity_applications`；字段只包含 application 身份、workspace、redirect URLs、状态和时间戳，唯一约束为 `(workspace_id, application_key)`，没有 credential secret 列。
- `internal/infrastructure/persistence/database/auth/auth_application_store.go` 使用 workspace-scoped ORM select 和按方言参数上限分批的 multi-row upsert；重复注册只刷新 source-owned redirect URLs，并保留管理员拥有的 status。
- authorization code redirect 校验经 `AuthorizationRedirectRegistered` 直接读取 `_identity_applications`；密码登录的 `ApplicationRegistered` 经 `AuthApplicationRegistrationService.Registered` 读取同一 repository，不依赖 Catalog revision。
- standalone server ready 前通过 SDK application registration 合约注册当前 browser application；local binding 与 remote SDK 的 application registration 都落同一 repository。真实 module 测试直接查询 `_identity_applications`，确认 `workspace-primary/orders-runtime` 只有一行。
- 本项验证命令：`go test ./internal/infrastructure/persistence/database/schema ./internal/infrastructure/persistence/database/auth ./internal/application/auth ./internal/adapter/identitysdk ./internal/transport/http/auth ./internal/transport/http/server ./internal/assembly ./module -count=1` 通过；其中真实 remote HTTP server 与 embedded module contract suite 均通过。

### 12.9 C2-C3 / E Catalog 删除证据

- Identity principal 直接聚合已发布 RoleSchema 的 exact `Permissions` 与既有 data/field/reference/export policy，再以数据库 Permission current snapshot 过滤 unknown/disabled/retired；没有 catalog published 前置条件或 catalog 二次裁剪。
- SDK 已无 catalog DTO、client、binding 和 revision API；remote retry allowlist 中残留的 `/identity/catalog/revision` 已删除。Runtime 已无 `identity_catalog.go`、catalog publisher、Notification catalog 拼装或 Identity 资源镜像。
- Identity fresh schema、ownership 和 portability specs 不包含 `_identity_authorization_catalogs` / `_identity_authorization_catalog_revisions`；原 `identitycatalog` persistence package 已删除。schema checksum 只列出 `identity_applications` 与 `identity_permissions` 两个新 current-state 边界。
- 代码未上线，因此没有 catalog 回填、drop migration、compat owner、双写或旧 receipt；application 和 permissions 都只从当前注册/Action source 初始化。
- 全仓 Go 源码扫描在 Identity、Identity SDK、Runtime 中无 `CatalogRevision`、`authorization catalog` API/store、`catalog_not_published`、`identity_catalog` 或 `CurrentRevision()` 生产残留；同名 localization/metadata/authoring catalog 不属于授权 Catalog，保留其业务职责。
- 验证命令：Identity SDK `go test ./... -count=1` 通过；Identity `go test ./internal/application/identity ./internal/domain/identity/service ./internal/infrastructure/persistence/database ./internal/transport/http/server ./module -count=1` 通过，覆盖无 catalog JSON 的登录、角色解析、AccessBundle、真实 remote HTTP 和 embedded module 合同。

### 12.10 非 HTTP Action 与 embedded module 合并证据

- workspace-wide 管理员 Permission 与对应保留 Action 已删除；管理员角色只使用显式 same-key Permissions，非 HTTP 能力也必须有自己的 source-owned Action。
- 元数据 manifest 读取、reload、migration plan、对象计数以及 definition validate/upsert/disable/rollback 已拆成 8 个独立非 HTTP Action；application/domain service 分别检查自己的 exact same-key Permission，bootstrap 只携带 `identity.metadata.reload`。
- `IdentityActionRegistry.PermissionOwners()` 从冻结 registry 投影 canonical owners；standalone/embedded Identity core 在 HTTP server 装配前合并 Audit module 的 source-owned `modulehttp.Route.Action`，校验 `module:<surface owner>`，再逐 owner reconcile。当前数据库启动后包含 100 条 `identity:builtin` 与 7 条 `module:audit` PermissionDefinition，重复启动由 snapshot reconcile 保持幂等。
- standalone 的 Audit governance 路由从 module Action 取 `audit.governance.read` / `audit.governance.export` 并通过数据库 current Permission snapshot + exact RoleSchema grant 校验。`/tenant-admin/platform-capabilities` 同样使用 exact `identity.platform_capabilities.get`；`/permissions/effective` 与 `/tenant-admin/runtime-schema` 显式注册为 authenticated-principal Actions。
- 角色撤销、entitlement batch、access review、数据范围、组织可见性、菜单 seed 和权限启停均无聚合管理员特判；高风险角色只由 `RoleSchema.RiskLevel=privileged` 判定，不根据权限或 `admin/owner` 名字推断。
- AuthorizationRevision 输入包含完整 PermissionDefinition key/status/enabled fingerprint；测试同时证明未授予 Permission 的状态变化也会改变 revision，而已授予 Permission 被停用后会改变 revision 并从新 principal 中移除。
- 验证命令：`go test ./internal/application/identity ./internal/application/metadata ./internal/domain/metadata/validation ./internal/domain/identity/contract ./internal/domain/identity/service ./internal/assembly ./internal/transport/http/server -count=1` 通过；`go test ./... -run '^$'` 全仓编译通过。

### 12.11 RoleSchema 唯一功能授权与 current PermissionDefinition 治理证据

- `IdentityPermissionSet` 已删除功能 `Permissions` 字段，只保留 data/field/reference/export policy；`IdentityExpandRoleAuthorization` 只复制角色自身 `RoleSchema.Permissions`，permission set/group 不再产生 Action grant。
- effective-access 的功能权限来源只记录实际 `role_assignment`；permission set/group 仍可解释非功能 policy 组合，但不会被标为功能 Permission 来源。
- 角色直接发布和 governance validator 都从同一个数据库-backed immutable PermissionDefinition snapshot 判定新增选择，分别拒绝 unknown、retired、disabled；principal 构建也用该 snapshot 过滤后再计算 AccessBundle 与 AuthorizationRevision。
- governance report 对每个 `RoleSchema.Permissions` 引用与同一 snapshot 做关联，输出 `unknown`、`retired`、`disabled` drift；这些 key 保留在角色版本中供人工修复，但不会进入新 principal。
- 生产模型扫描无 `IdentityPermissionSet.Permissions` 或 `set.Permissions` 功能扩展逻辑；workspace-wide 管理员 grant、wildcard-shaped key 和 action alias 均不存在，也不能扩展为其它功能或数据权限。
- 验证命令：`go test ./internal/domain/identity/model ./internal/domain/identity/policy ./internal/domain/identity/projection ./internal/domain/identity/contract ./internal/application/identity -count=1` 通过；`go test ./... -run '^$'` 全仓编译通过。

### 12.12 Identity standalone 全 route/action matrix 与显式策略证据

- standalone 装配把 Core 内置/Audit Actions、Identity SDK browser Actions 与 standalone health/portability/Remote SDK/capability protocol Actions 合并进一个 `IdentityActionRegistry`；构造函数在注册完成后冻结 Foundation registry，之后只暴露 detached query，不提供运行时注册入口。
- `recordingRouteRegistrar` 在真实 `http.ServeMux` 挂载前按 `method + router template` 查询冻结 registry；找不到唯一 Action 时记录装配错误且不挂载路由。health、portability、Auth、Identity、Audit、direct、Remote SDK、capability 与 browser 全部使用这一个 registrar。
- browser URL 与 Action 仍由 Identity SDK 的 `browsergateway.ActionDefinitions` 单一拥有；standalone 只把同一 manifest 注册到临时 gateway mux，再经 host registrar 挂载，没有复制 14 条 URL 或 handler map。
- Audit 不再只手写挂载两条 governance URL；standalone 遍历 Audit `modulehttp.Surface.Routes()` 的 7 条 source-owned Actions，并用当前 route Action key 构造 owner principal 投影。数据库 current Permission gate 和 Audit application service 的领域内 exact gate 都保留。
- 登录入口统一声明 `authenticated`；Identity、Runtime endpoint/object/business Action adapter 以及 module surface 投影通过是否携带 Permission 区分“仅登录”和“同 key 功能权限”，Permission 仍要求与 Action key/owner 相同。
- 双向覆盖测试锁定当前 152 条 standalone 路由：每条 route 都解析到一个 Action、每个 HTTP Action 都已挂载、strategy 非空、listener 分类与 Action exposure 一致。额外负例证明未注册 route 在进入 mux 前失败；inventory 排序集合 SHA-256 为 `b7cbb5f7256fd02a4a7b1b47ee1314e520e97832447ffe7ab2481c1de0c983d0`。
- exposure 校验发现并修复 `/identity/application-service/token` 与 `/identity/application-service/verify` 被旧 listener classifier 错分为 tenant-admin 的问题；它们现在从 public listener 可达，但仍必须通过 source-owned application service credential。
- 验证命令：Identity `go test ./internal/transport/http/server -run 'TestStandaloneRouteInventory|TestRecordingRouteRegistrar|TestClassifyRouteSurface' -count=1` 与 `go test ./... -run '^$'` 通过；Foundation `go test ./action ./modulehttp ./modulecapability -count=1` 通过；Runtime 的 Action/endpoint/bootstrap/HTTP/runtimehost 相关分组通过。

### 12.13 D1 SDK reconcile/application/revision 合约证据

- SDK `PermissionReconcileRequest` 现在显式携带 `previous_snapshot_hash` 与 canonical `snapshot_hash`；`PermissionSnapshotHash` 对 definition 顺序不敏感，并将 owner、key、resource/operation、文案、分类和 source kind 纳入 hash，同时排除数据库 ID、时间、lifecycle 与管理员 `enabled`。hash 不匹配、previous hash 非规范 SHA-256、owner/definition 非法时在发出请求前返回稳定错误码。
- Identity adapter 不再读取数据库当前 hash 后替远程调用方补 CAS；它把调用方提交的 previous/new hash 原样传入 application/store 原子 reconcile。相同 snapshot 的重试允许幂等成功，旧 snapshot 在新 snapshot 生效后返回 409 `identity.permission_snapshot_stale`，owner 抢占返回 409 `identity.permission_owner_conflict`。
- receipt 返回 workspace、source owner、previous/new hash、definition count 和 inserted/updated/retired/unchanged。Runtime 在候选激活前逐字段核对 receipt；错误 owner/hash/count 即使 HTTP 返回成功，也以 `identity.permission_reconcile_receipt_invalid` 拒绝候选。metadata activation 以上一冻结 registry 的 owner hash 为 CAS 基线，owner 整体移除时提交空 snapshot 使旧定义 retired。
- remote reconcile 继续使用 application service credential，并新增 `IDENTITY_APPLICATION_PERMISSION_OWNERS` 配置，将每个 tenant/workspace/application credential 显式绑定可发布 owner 集合。错误 workspace/application 或普通 bearer 返回 401；有效 credential 越出 owner scope 返回 403 `identity.permission_source_owner_forbidden`。credential secret 仍只在既有 secret/config 边界，不进入 `_identity_applications`。
- embedded local binding 与真实 remote HTTP server 均验证 application registration、完整 receipt、幂等、stale CAS 和 owner conflict；embedded 继续复用 host executor，remote 由 Identity standalone transaction 提交。定义 reconcile 与 RoleSchema 授权选择仍是两个独立 API/repository 边界。
- AuthorizationRevision 仍由 principal/access snapshot 合约返回，SDK principal resolver 的 cache key 包含 workspace/subject/revision/token，超过显式最大陈旧窗口后拒绝旧 revision；没有恢复 CatalogRevision。
- 验证命令：SDK `go test ./authorization ./application ./remote ./authorization/principal -count=1`；Identity `go test ./internal/adapter/identitysdk ./internal/infrastructure/persistence/database/identity/authorization/permission ./internal/transport/http/remotesdk ./internal/transport/http/server ./module -count=1`；Runtime `go test ./runtime/bootstrap/runtime -run 'TestRuntimeAuthorization' -count=1`，全部通过。Identity、SDK、Runtime 全仓 `go test ./... -run '^$' -count=1` 也已通过编译。

### 12.14 B3 / D2 Runtime 默认对象 Action 与候选激活证据

- `runtime/domain/action/projection/DefaultActionsForObject` 是唯一对象默认 Action 生成器；`BuildAuthorizationRegistry` 只遍历当前 `ApplicationSchemaSnapshot.Objects`，因此内部 persistence table 不会因表存在而生成 Permission。`BuildSchemaSnapshot` 会把每个成功构建的 ObjectSchema 归一化为显式 capability set。
- 标准对象只生成文档规定的 create/read/update/delete/export 五个 same-key Action/Permission；本轮复核删除了超出文档的 `object.import` capability/Action。CSV import 业务路由仍保留，并回到其已有的显式 Runtime endpoint Action/strategy，不会伪造第六个对象默认 Permission。
- capability false 与 append-only lifecycle 会在生成前裁剪 update/delete/export 等不可执行项；`system_object` 不参与跳过判断。测试中的 `record_timer` 作为 system object 仍生成 `record_timer.read`，而显式 read-only 对象不会生成 create。
- 对象 Action 同时带 concrete display URL 和 `runtime_object_action/<object>.<operation>` binding。通用 router 只从 path 提取 object/action，查询冻结 registry 中已存在的具体 `authenticated` Action，然后检查其同 key Permission；unknown object、unsupported capability、跨对象 authored Action 和短别名全部 fail closed。源码扫描无 `static_permissions_all/any` 或 `dynamic_permission_resolver`。
- Runtime registry 由对象默认 Actions、authored Actions、generated `EndpointContracts`、Runtime inventory surface 和所有 `modulehttp.Surface` 统一合并、校验并冻结；启动在构造 HTTP Runtime/ready 之前完成 application registration、逐 owner CAS reconcile 和 receipt 全字段核对。
- metadata reload 使用 `ApplicationSchemaReloadPreparation{Commit, Abort}`：先构建并冻结候选 registry，再 reconcile Identity；Runtime schema、Action catalog 和 authorization registry 仅在 workflow 同步成功后以 no-fail commit 一次替换。后续失败按 candidate hash 补偿回上一 owner snapshot；多 owner reconcile 中途失败也按逆序补偿已确认 owner，补偿失败不会被吞掉。静态 project roles 不再在每次 metadata reload 中重复发布。
- Runtime 的 record/data/field/reference/export 判定继续接收当前 ObjectSchema 与 AccessBundle policy facts；Identity reconcile payload 只含 PermissionDefinition，不镜像对象字段、关系或数据策略。
- 验证命令：Runtime `go test ./runtime/domain/action/projection ./runtime/domain/appschema/validation ./runtime/domain/appschema/contract ./runtime/application/appschema ./runtime/bootstrap/runtime ./runtime/transport/http -count=1` 与 `go test ./... -run '^$' -count=1` 通过；Identity `go test ./internal/domain/metadata/contract ./internal/application/metadata ./internal/domain/metadata/validation -count=1` 通过。测试覆盖 candidate reconcile 失败、workflow 后续失败触发 abort、跨 owner 中途失败补偿、旧 frozen registry 保留和 receipt 不匹配拒绝。

### 12.15 B2-B2.1 exact Identity Action、authoring 与页面投影证据

- `IdentityBuiltinAuthorizationActions()` 当前包含 119 个显式 Actions，其中 89 个由 `identity:builtin` 拥有 same-key Permission；list/get/search/versions、create/update/delete 及 disable/enable/unlock/force_logout/assign/revoke/approve/reject 等均为独立 Action，不共享 broad read/write grant，也不定义 workspace-wide 管理员 Action。
- `IdentityActionRegistry.ProjectAuthoringDomain` 收集每个 capability 的 `ConfigurationRoutes`、`ValidationEndpoint`、preview/simulation 和全部 `ResourceOperations`，逐项解析到冻结 registry；role/self Action 必须存在 same-key、same-owner Permission，最终 `Permissions` 与 `Execution.PermissionModel=exact_action_same_key_permission` 由投影生成。任何未注册 route 会使 contract 构造失败。
- OpenAPI capability、legacy authoring response 和三份生成的 management authoring JSON 均消费该投影；raw authoring capability 不再硬编码功能 Permissions。catalog 测试逐条证明投影 permission 必须反查到 canonical Action，而不是维护第二套词汇。
- Action matrix 的 page binding 生成 `identity-admin-page-permissions.json`；前端 route registry 从该生成物设置页面 entry permission，后端 menu seed/assignment validation 从同一个 frozen registry 查询页面 permission。旧 `identity_admin_routes.go` 已删除。
- transport authoring helper 已删除自由传入 permission string 的参数；所有 functional permission 先由 `registerIdentityAction`/`identityAction` 按 route 对应 Action 统一执行，authoring executor 内只保留 known workspace scope 校验。
- 生产代码、默认 seed、前端和测试 fixture 的旧 Identity broad key 及 workspace-wide 管理员 key 扫描结果为 0；未增加 alias evaluator、兼容迁移或双重 grant。外部登录高风险角色只认声明的 `RoleSchema.RiskLevel=privileged`，不根据权限 key 或 `admin/owner` 名字推断。
- 验证命令：`go test ./internal/application/authoring ./internal/application/identity ./internal/domain/identity/contract ./internal/domain/authoring ./internal/domain/metadata/contract ./internal/transport/http/identity ./internal/transport/http/server ./cmd/identity-management-contracts -count=1` 通过；Identity Admin `routes:check`、29 个文件/104 个 unit tests 和 `tsc -b` 通过；`git diff --check` 通过。
- 当前 Identity 仓最终全量 `go test ./... -count=1` 通过；覆盖 application/domain、所有数据库与三方言 renderer、assembly/module、全部 HTTP transport 和真实 standalone/embedded 集成测试。`TestStandalonePermissionAPIProjectsDatabaseStateAndActionBindingsWithRoleEnforcement` 从 fresh DB 读取 107 条启动自动同步记录，`module/factory_test.go` 证明重复 reconcile 与 reopen 不重复插入。

### 12.16 F2-F3 权限管理展示与治理投影证据

- 角色功能权限 view-model 先按数据库 definition 的 category、canonical `source_owner`、`source_kind` 和 resource 分组，再展示 capability/operation；每个 operation 同时展示 active/retired 与 enabled/disabled，只有 active+enabled 才可新增选择。
- Identity 内置 resource 使用 Action 定义文案；object permission 的资源名由管理端已加载的 Runtime schema snapshot 按 object key 覆盖。data-scope/field 选择也继续直接消费 Runtime schema objects/fields，不从 `_identity_permissions.resource_key` 反建 ObjectSchema。
- 前端已删除 `MODULE_PERMISSION`、`MODULE_PERMISSION_KEYS`、`PermMatrix` 和无消费者的 `Role.perms` 兼容投影；按钮直接检查自己的 exact Action key，角色编辑只消费数据库 catalog 中的 canonical permission keys。
- effective-access explain 输出递归 reason tree、allowed decision、AuthorizationRevision、role assignment grant source 和 guardrail deny 节点。access review item 新增只读 `permission_states`，每次读取按当前 immutable PermissionDefinition snapshot 重新投影 active/disabled/retired/unknown 与 canonical owner；该字段不写 access-review 表，也没有 permission revision/publication 实体。
- 验证命令：Identity Admin 29 个文件/106 个 unit tests 与 `tsc -b` 通过；Go `go test ./internal/application/identity ./internal/domain/identity/model ./internal/infrastructure/persistence/database/identity ./internal/infrastructure/persistence/database/identity/integrationtest -count=1` 通过；`git diff --check` 通过。

### 12.17 通用 embedded module Action contribution 证据

- `assembly.Options.ModuleHTTPProviders` 与 `Core.ModuleHTTPProviders` 直接承载 Foundation `modulehttp.Provider`，没有新增平行 surface/permission 合约。Audit 也只是 provider 列表中的一个成员，原 `registerAuditRoutes` 专用挂载路径已删除。
- assembly 对每个 `Surface` 执行 `modulehttp.ValidateSurface`，并强制每条 `Route.Action.Owner == module:<surface.Owner()>`；所有 provider Actions 与 Identity built-ins 一次合并、一次冻结，owner 冲突、route 冲突、same-key Permission 不合法均在 ready 前失败。
- 冻结后 `PermissionOwners()` 逐 owner reconcile source-owned definitions；只有全部 receipt 成功，server 才遍历同一 provider 列表挂载 handler。canonical owner 保持 source module，Identity 只作为 host/storage authority，不改写 owner。
- 通用 host gate 先执行 resolved Action strategy 与数据库 current Permission 检查，再把仅含当前 exact Action grant 的 Identity SDK principal 放入 module request context；module handler/application service 自己的领域校验仍保留，任何其它 Permission 都不会被投影成 module grant。
- `TestStandaloneGenericModuleContributionReconcilesBeforeMountAndUsesHostGate` 使用非 Audit 的 `module:inventory` surface，证明 permission 在挂载前入库、无权限请求不会调用 handler；`TestStandaloneRejectsModuleActionOwnerMismatchBeforeReady` 证明 owner 错误拒绝启动。验证命令：`go test ./internal/assembly ./internal/transport/http/server -count=1` 通过。

### 12.18 Identity policy 结构校验与 Runtime 最终语义校验证据

- Identity `MetadataApplicationService` 通过窄接口 `MetadataPermissionSelectionValidator` 一次批量提交候选 RoleSchema 与 profile binding 引用的外部功能 key；生产 assembly 注入数据库 backed `IdentityPermissionCatalogApplicationService`，unknown、retired、disabled 均按当前 PermissionDefinition fail closed。同一候选中新建的 authored Action 拥有自己的 same-key Permission，不要求先落库再验证，也不会重复查询 DB。
- 原 `ReplaceAuthorizationObjects`、`authorizationObjects` 缓存和 `MetadataValidateIdentitySchemaWithAuthorizationObjects` 已删除。Identity 不保存或缓存 Runtime ObjectSchema；RolePermission 校验 exact permission key 与五种规范 scope，field/reference policy 继续校验各自字段形状。Identity 自己拥有的 metadata object 仍执行本地结构引用校验。
- 原 profile binding 逻辑曾把所有 `RoleSchema.Permissions` 收集成“已知权限”再验证 `required_permissions`，会让角色反向成为 Permission 定义源；该逻辑已删除，`required_permissions` 与角色功能 key 一起交给当前 PermissionDefinition validator。
- Runtime `manifest_role_authorization_validation.go` 在 metadata candidate 激活前使用候选 `ObjectSchema` 最终校验 data predicate relation path、字段存在/disabled 状态、field permission、reference relation/target/display fields 和 export fields；无界或当前不能编译的 predicate operator 在候选阶段拒绝，不推迟到请求执行。
- Identity 测试 `TestMetadataCandidateValidatesExternalPermissionKeysAsOneCurrentStateBatch` 证明去重后的外部 key 只调用一次 validator，候选 Action key 不查 DB；`TestMetadataCandidateFailsClosedWhenCurrentPermissionValidatorIsUnavailable` 和 `TestMetadataCandidateRejectsUnknownCurrentPermissionKey` 锁定 fail-closed。`TestMetadataIdentityAuthorizationValidatesStructureWithoutMirroringRuntimeObjects` 锁定 Identity 的结构边界。
- Runtime 测试覆盖 RolePermission permission_key/data_scope、disabled field、reference relation/display field、export field负例。验证命令：Identity `go test ./internal/domain/metadata/validation ./internal/application/metadata ./internal/assembly -count=1`；Runtime `go test ./runtime/domain/manifest/validation ./runtime/application/appschema -count=1`；两仓 `git diff --check`，全部通过。

### 12.19 HTTP、workflow、automation、timer、integration、agent 与 bulk 的同一 Action 执行边界

- Runtime 只有一个 `ActionApplicationService.Invoke` governed boundary。调用方只能提交 stable `ActionKey`、object/record、principal、input 与幂等键；入口类型由可信 adapter 传入并覆盖 DTO 中伪造的 `Source`，随后统一执行 Action catalog resolution、exact same-key Permission、data/object policy、payload、assurance、idempotency、owner handler、commit 和 audit。
- HTTP record Action、workflow、automation、record timer/job、Integration trigger、agent tool 和 bulk 都调用同一个 `Invoke`；RPC/connector 类协议 adapter 不维护自己的 permission 字符串，而是把目标 `action_key` 转成 `ActionInvocation`。未知 source、未知 Action、object mismatch 或缺少 exact Permission 均在 handler 前 fail closed。
- durable automation outbox 在执行时重新解析当前 principal，不冻结排队时角色快照；agent task continuation 同样重新授权 durable execution identity。Permission 被停用或角色撤权后，后台任务不能凭旧 snapshot 继续执行。
- `TestBusinessActionArchitectureHasOneInvocationAndMutationExecutor` 扫描生产源码，锁定 handler/system operation 只能从 governed boundary 到达，并逐一检查 HTTP、workflow、automation、record timer、agent、bulk adapter。新增 `TestEveryInvocationSourceUsesTheSameExactActionPermissionBoundary` 对 HTTP、workflow、automation、record timer、integration、agent、nested、bulk 八种 source 逐项验证：缺少 `order.approve` 全部拒绝，拥有同 key Permission 全部经同一执行/audit 路径成功，且伪造 source 被覆盖。
- 验证命令：Runtime `go test ./runtime/application/action -run 'TestEveryInvocationSourceUsesTheSameExactActionPermissionBoundary|TestActionInvocationNormalizationAndProjection' -count=1`、`go test ./runtime/domain/action/service -run TestBusinessActionArchitectureHasOneInvocationAndMutationExecutor -count=1`、automation current-permission revalidation 与 workflow agent continuation reauthorization 两项定向测试均通过；本轮最终扩大到 Runtime `go test ./...` 全量通过。

### 12.20 F2 live Action usage query 证据

- Foundation `action/usage.go` 定义一个按 canonical owner + permission keys 批量查询的 `PermissionUsageProvider` 合约。请求和响应均固定 contract version、排序并拒绝重复 owner/key；响应显式区分 `available=false` 与“owner 可达但没有匹配 usage”，并逐项验证返回 Action/Permission 的 owner、same-key 与请求范围。
- Identity `IdentityPermissionCatalogApplicationService.List` 只从数据库读取 current PermissionDefinitions；本地 `identity:builtin` usage 直接由冻结 registry 投影，外部 owners 合并成一次 provider 调用。远程错误或 owner 未加载时保留数据库 definition 并投影 `unavailable`，usage 不写 `_identity_permissions`，也没有缓存上次远程响应。
- embedded Runtime 把原子发布的冻结 Action registry snapshot 通过 SDK `PermissionUsageProviderBinder` 直接绑定给 Identity。`module/factory_test.go::TestFactoryOpensDirectSDKBinding` 使用真实 module HTTP permission catalog 证明外部 `customer.read` 返回当前 registry route usage。
- standalone Identity 的 `internal/infrastructure/runtimeactionusage` 是明确的 outbound adapter：同一次目录请求只发一个有大小、超时和严格 JSON 边界的 HTTP batch；它要求已有 authenticated management context，但跨服务只发送独立短期 token，不转发浏览器 bearer 或 ops token。token 仅包含 `runtime.authorization.action_usages#query`，校验 application、audience、credential rotation、单一 grant 与 expiry 后才缓存。
- Runtime 的 `POST /operations/authorization/action-usages/query` 属于 Runtime module inventory surface，直接查询当前 frozen registry。它声明 `signed`，host 从 Action policy 派生 exact grant，并要求 Action audience 与 Runtime Binding audience 相同；缺 token、错误 token、grant/audience drift 均在 handler 前拒绝。
- SDK 将完整的 `ApplicationServiceAuthentication` 与窄 `ApplicationServiceTokenVerifier` 分开。remote binding 同时提供 exchange/verify；本地 Identity 和 embedded module 只提供 verifier，类型上不再宣称一个会返回 501 的 exchange 能力。application scope decorator 根据 delegate 的真实能力选择包装类型，测试证明 verifier-only binding 无法断言成完整 binding。
- `TestStandalonePermissionAPIQueriesRemoteRuntimeUsageWithoutPersistingIt` 通过真实 Identity standalone HTTP 登录和权限目录 API，验证 source-owned external Permission 的 live usage、独立 service bearer、workspace/request ID、local/remote token verification；随后令 Runtime 返回 503，第二次读取仍返回数据库 definition，但 usage 立即为 unavailable 且没有持久化 fallback。
- 独立部署配置使用 `IDENTITY_ACTION_USAGE_RUNTIME_URL`、timeout、source application、Runtime audience 与 credential ID；source rotation 必须真实存在于既有 `IDENTITY_APPLICATION_SERVICE_CREDENTIALS`。生产 URL 强制 HTTPS，README 已记录完整调用与故障语义。
- 验证命令：Foundation `go test ./action -count=1`；SDK `go test ./... -count=1`；Identity `go test ./internal/application/identity ./internal/infrastructure/runtimeactionusage ./internal/platform/config ./internal/adapter/identitysdk ./internal/assembly/module ./internal/transport/http/identity ./internal/transport/http/server ./module -count=1`；Runtime `go test ./runtime/bootstrap/runtime ./pkg/runtimehost -count=1`。以上命令与三仓 `git diff --check` 均通过。

### 12.21 Notification 首个 module SOP 样例证据

- Notification 的唯一权限事实源是 `internal/application/authorization_actions.go::AuthorizationActions`：61 个 HTTP Actions 全部声明 canonical `module:notification` owner、stable key、capability/operation、strategy、binding 与 governance；其中 21 个管理 Action 使用 `authenticated` 并拥有 same-key Permission，40 个 Business/Portal Inbox Action 同样使用 `authenticated` 但没有角色 Permission。
- `ProductRoutes()` 只对该 manifest 调用 `modulehttp.RouteFromAction`；`NewSurface` 只维护 `action_key -> handler` 实现绑定，并用 manifest 的 `route.Pattern()` 挂载。缺 handler、额外 handler、重复 Action/route 在 ready 前失败，没有第二份 Method/URL 表。
- module binding 与 SaaS remote binding 都实现 Foundation `action.Provider` 并返回同一 manifest；Surface routes、OpenAPI operations、module capability category 和 SaaS projection 逐 Action 做深度相等/集合相等测试。Identity SaaS 接线也只从 `Action.Permission != nil` 批量生成 owner snapshot，读取最后确认 hash并核对完整 receipt。
- resumed publication 只使用 `notification.publications.approve`；旧 direct-publish tombstone、`notification.template.*`/underscore 旧角色权限和 Runtime Notification-specific Permission hardcode 已从生产源码删除，没有 alias、双 grant 或兼容 endpoint。Notification 测试中的聚合 workspace 管理员 fixture 也已删除。
- module application service 仍按同一个 Action key 拆分 resource/action 调用 Identity reauthorization，并保留领域内 fail-closed；host gate 不是唯一授权边界。测试证明另一 exact Permission 不会进入 mutation reauthorization。
- 验证命令：Notification `go test ./... -count=1 && go vet ./... && git diff --check` 通过；Runtime 生产源码扫描只剩通用 module Action contribution，不含 Notification Permission vocabulary hardcode。

### 12.22 B4 stable Action key、升级与卸载证据

- Foundation `modulehttp.TestHTTPBindingChangePreservesActionAndPermissionIdentityWithoutAlias` 用同一个 source-owned Action 只修改 HTTP Method/URL binding，断言 Action key 与 same-key Permission identity 均保持不变，并且旧 URL 不再解析；registry 中没有 alias 或第二份 grant。
- Runtime `TestRuntimeAuthorizationReconcileCarriesPreviousHashAndRetiresRemovedOwner` 证明升级时每个 owner 都携带上一份已确认 snapshot hash；owner 从当前 registry 消失时提交空 snapshot，Identity 将该 owner 的定义 retire，而不是保留旧 key 或生成卸载别名。
- Runtime `TestRuntimePermissionReconcileCompensatesEarlierOwnersOnBatchFailure` 证明多 owner 批量 reconcile 中途失败时，已确认 owner 按原 snapshot 逆序补偿，失败候选不会被部分激活。
- Identity `TestPermissionReconcileRetiresRestoresAndRejectsConflictingSnapshots` 覆盖完整 snapshot 的幂等重放、移除后的 retire、canonical owner 恢复、跨 owner key 冲突拒绝和“服务端已提交但响应丢失”后使用原 previous hash 重试；重试返回当前相同 snapshot，不重复插入或制造兼容定义。
- 2026-09-02 验证命令：Foundation `go test ./modulehttp -run TestHTTPBindingChangePreservesActionAndPermissionIdentityWithoutAlias -count=1`；Runtime `go test ./runtime/bootstrap/runtime -run 'TestRuntimeAuthorizationReconcileCarriesPreviousHashAndRetiresRemovedOwner|TestRuntimePermissionReconcileCompensatesEarlierOwnersOnBatchFailure' -count=1`；Identity `go test ./internal/infrastructure/persistence/database/identity/integrationtest -run TestPermissionReconcileRetiresRestoresAndRejectsConflictingSnapshots -count=1`，三组均通过。

### 12.23 B5 permission wrapper 与 workspace-wide 特权清理证据

- 删除 `internal/domain/identity/policy/identity_permission_policy.go` 及其重复测试；应用层和数据库集成测试直接依赖 `internal/domain/identity/contract` 中唯一的 `IdentityRoleHasPermissionKey` / `IdentityRoleAllows` 实现，不再经过 permission policy facade。
- 删除仅为兼容调用名保留的 `IdentityRoleHasExactPermissionKey`；所有调用统一使用本来就是 exact-only 的 `IdentityRoleHasPermissionKey`。生产源码扫描不存在该旧符号。
- 删除字段 read/write/export/mask 和字段权限投影中的 `workspace.admin` 特殊分支。新增 `TestWorkspaceAdminShapedPermissionDoesNotGrantFieldAuthority`，证明该形状的字符串不能越过 sensitive/default-deny 字段策略、显式字段 grant 或 mask。
- Identity HTTP route registrar 只以 Action key 绑定 handler，再从冻结 registry 读取 Method、URL 和 authorization strategy；没有第二个 route permission 参数。仍需跨 application service 复用的少量 Action 常量集中在 `identity_builtin_action_keys.go`，文件注释明确其 canonical owner 为 `identity:builtin`。
- 验证证据：选定生产源码扫描 `IdentityRoleHasExactPermissionKey|workspace\\.admin|workspace\\.ADMIN|static_permissions_(all|any)|dynamic_permission_resolver` 为 0；`go test internal/domain/identity/contract/identity_authorization_contract.go internal/domain/identity/contract/identity_object_access.go internal/domain/identity/contract/identity_object_access_test.go` 通过；`git diff --check` 通过。全 package 测试另由全量 gate 项统一复核。

### 12.24 最终收口与复审证据（2026-09-02）

- 权限键语义完成去歧义：完整可执行键只使用 `ActionDefinition.Key`；`PermissionDefinition` 的末段动作统一命名为 `OperationKey`，wire 与 `_identity_permissions` 列统一为 `operation_key`。Foundation 现在同时强制 `Permission.Key == Action.Key == ResourceKey + "." + OperationKey`，错误分段在注册/冻结前即失败，SDK reconcile 保留同一约束。`IdentityActionPermissionUsage.ActionKey` 继续明确表示完整 live Action key，不与持久化 definition 混用。Foundation、Identity SDK、Identity、Runtime 及 module Action contributors 已同步全量测试。
- principal 构造改为 fail closed：空 subject 以及没有有效角色的 subject 都不会再被推断为 `admin`、`developer` 或全量数据权限；多角色按 exact Permission key 合并各自的 RolePermission grants，不再维护平行的角色级范围字段。回归测试锁定空主体/无角色主体不能获得数据权限，并覆盖五种规范 scope 的并集。
- OrganizationUnit 的 `path`、`ancestor_ids`、`depth` 改由 Identity 根据 ID/parent graph 生成，调用方输入不会成为层级事实；reparent 会一次重算完整子树，memory 先完整校验再加锁写入，SQL 在宿主 transaction 或本地 transaction 中整批提交，失败时不暴露半棵新树。
- Identity Admin 删除按 `role.id == admin` 或 `builtIn` 推断权限/数据范围的分支；角色功能、对象范围、字段权限和菜单都只读取后端实际配置。当前 unit 为 26 个测试文件、96 个测试，通过 `tsc -b` 与 Vite production build。
- Notification team inbox 从已认证 principal 的 `ReportingScopeUserIDs` 构造 `ReportingUserIDs`，不信任请求方声明关系；指定成员不在该集合时由领域 validator 拒绝。agent/tool 等委托入口统一声明 `signed`，并明确不生成角色 Permission。
- 本重构触及的 DML 使用 domainry-orm。Runtime evidence schema 中遗留的 worker-scope delete 与 publication dedup backfill 已改为 ORM delete/update builder；结构复制等 ORM 无等价能力的既有 migration raw SQL 未被冒充为本授权重构成果。
- 全量验收：Identity `go test ./...`、Identity SDK `go test ./...`、Runtime `go test ./...`、Foundation `go test ./...`、Notification `go test ./...` 全部通过；Identity、Identity SDK、Runtime、Notification `go vet ./...` 全部通过；Identity Admin `npm run test:unit` 与 `npm run build` 通过。相关 Metadata、Lifecycle、Audit、Agent SDK、Scheduler SDK、Monitoring SDK、Integration SDK 也完成全量编译/测试，其中需要本机端口的测试在允许监听临时端口的环境执行。
- 最终 TODO 扫描 `rg '^- \[ \]' docs/identity-authorization-refactor-todo.md` 为 0；历史“先做 S0 再决定是否扩大”的流程项已明确标记为被用户后续继续开发指令解除，没有将它们伪装成新的代码工作。

### 12.25 角色与策略直发边界最终收口证据（2026-09-02）

- 新增并注册 `identity.roles.create/update/delete`、`identity.role_permissions.publish`、`identity.role_field_permissions.publish` 五个 exact Actions。每条角色授权 Action 只校验同 key Permission，由同一 Action registry 自动 reconcile PermissionDefinition，没有 broad grant 或 `workspace.admin` 旁路。
- `IdentityRoleDefinitionPublicationService` 是唯一角色写用例入口，窄端口显式区分角色增改删、功能权限、数据范围与字段权限。每个 metadata command 使用自己的 Action 加载并发布 RoleSchema；`TestRolePermissionPublishRequiresOnlyItsExactAction` 和真实 HTTP 限权用例证明 publish 不会暗中申请 list Permission。
- `POST /identity/roles` 只接收可验证的 RolePermission grants；每个 grant 必须有规范 data scope，新角色没有 grant 即 fail closed，并清空调用方夹带的字段、引用、导出、可授予角色、guardrail 和跨 workspace 配置。通用 `PATCH` 只改名称、描述和 i18n；授权字段由专用端点修改，避免一个宽 DTO 覆盖整份授权。
- Permission 与其 data scope 在同一角色权限页面、同一次 RoleSchema revision 中读取和 CAS 发布；字段权限仍由自己的治理入口管理。角色授权相关源码不再引用 `systemChangePlansApi`、`saveSystemResourceDraft` 或 `roleAuthorizationPlanID`。
- Permission 发布以单个 grant 为原子配置，不存在对象级数据范围的单独发布。字段权限发布仍只替换自己负责的字段；前端编辑时一次只允许选择一个角色，dirty 状态锁定角色选择。
- 角色删除在发布 disabled definition 前检查用户角色分配和角色菜单分配；有引用即返回 conflict。所有成功写入继续复用既有 `_identity_role_definitions`、`_identity_role_definition_versions` 和 `_identity_roles` 投影，没有新增 role-permission 表、Change Plan 表、目录层级或第二份授权 authority。
- `TestStandaloneRoleAndPolicyAuthoringPublishesRoleSchemaDirectly` 在真实 SQLite、HTTP、登录和 Action gate 上证明：创建为 version 1 且注入的高权限被清空；相同幂等键精确重放不增加 version/audit；数据与字段发布只改对应字段；通用更新保留全部授权策略；删除禁用运行态角色目录。相关版本数、schema hash 与审计事件均逐步断言。
- 最终验证：Identity `go test ./... -count=1`、`go vet ./...`；Identity Admin `npm run test:unit`（26 files / 96 tests）与 `npm run build`；`git diff --check` 均通过。当前 registry 为 119 个 Identity Actions / 89 个 `identity:builtin` same-key Permissions，standalone route inventory 为 152 条，SHA-256=`b7cbb5f7256fd02a4a7b1b47ee1314e520e97832447ffe7ab2481c1de0c983d0`。
- 架构复审结论：角色授权的定义源是 source-owned Action，current 开关源是 `_identity_permissions`，角色选择唯一写入 versioned `RoleSchema`，Runtime 只执行当前对象的数据/字段策略；四层职责没有交叉持有同一事实。此次收口只在既有 application/domain/transport/frontend 目录内使用职责明确的文件名，没有新建平行权限包或部署目录。

### 12.26 客服支持组织数据范围收口证据（2026-09-02）

- [x] `_identity_users` 增加可空 `support_org_id` 和 `(workspace_id, support_org_id)` 索引；fresh schema、现有库 `EnsureColumn`、ORM upsert/select/page query、portable dataset、subject export/erase 全部使用同一列，没有新表、第二 migration ledger 或 relation 前缀。
- [x] `IdentityUser.OrgID` 继续表示客服真实所属部门；`SupportOrgID` 是独立可选事实。用户创建/更新 authoring contract、manifest seed、HTTP DTO、管理端列表编辑和详情编辑均支持该字段，管理端只允许选择 active 组织并能清空配置。
- [x] 用户写入时校验 `support_org_id` 必须引用 active OrganizationUnit；principal 解析时从当前组织邻接图派生该节点及全部 active descendants，写入 `SupportOrgScopeIDs`。目标缺失、禁用或派生为空时不发布可信 scope，授权 revision 同时包含用户字段和派生集合，组织或配置变化会生成新 revision。
- [x] 角色模型不存在 `DataPermission`；`RoleSchema.Permissions[]` 中每个 exact Action grant 自带 data scope。AccessBundle 的 `DataPolicy` 只是按 exact action 编译出的执行投影，不能独立创造 FunctionGrant。
- [x] 客户应用角色使用规范 `target_org` scope：编译为 `owner_org_id IN $subject.support_org_scope_ids`，不新增客户专属 Permission key 或 Identity 对客户对象的所有权。Metadata validation 仍由对象 owner 校验 `customer` 与 `owner_org_id`，Identity 只提供可信组织事实。
- [x] SDK 适配边界把同一对象过滤条件编译到 evaluator 的查询/变更技术通道；这两个通道不是角色 grant。真实 evaluator 测试证明 `customer.read` 可读取支持组织及 active 子组织、组织外记录拒绝、空支持范围 fail closed，且匹配记录也不能执行未声明的 `customer.update`。
- [x] 多角色同对象范围按并集编译；测试证明客服真实组织范围与额外销售支持范围都可读，第三方组织仍拒绝，避免 `organization + custom` 聚合时丢失任一分支。
- [x] 验证通过：Identity `go test ./... -count=1`、`go vet ./...`、全仓 `go test ./... -run '^$' -count=1`；Identity Admin `npm run test:unit --workspace identity-admin`（26 files / 96 tests）与 `npm run build --workspace identity-admin`；`git diff --check`。全量 Go 测试在允许 `httptest` 监听本机临时端口的环境执行。
- [x] 架构复审确认本项只修改既有 user、principal、policy projection、SDK adapter、schema/repository、管理端 user form 与文档位置；没有新增业务化权限包、平行目录或数据库表。独立数据范围管理页已删除，业务应用通过 source-owned RoleSchema 的逐 Permission grant 声明范围。
