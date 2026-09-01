# Identity 权限体系重构 TODO

状态：S0 standalone 纵向切片实施中；Action/Permission 存储、读取、展示和门禁已完成，RoleSchema 发布链的宿主所有权待确认

更新日期：2026-09-01

关联设计：[identity-authorization-refactor.md](identity-authorization-refactor.md)

模块接入流程：[module-authorization-onboarding-sop.md](module-authorization-onboarding-sop.md)

## 0. 执行约束

- [x] 本文档作为本次权限重构的唯一开发清单；每完成一项，连同代码、测试和验收证据一起勾选。
- [x] 不使用 Domainry Builder，不创建 `.domainry` 开发任务，不运行 Builder 的 model/apply/verify 流程。
- [x] 不使用 worktree；直接在当前 Identity、Runtime、SDK 仓库按批次修改。
- [x] 任何数据库只有一个宿主拥有的 `_schema_migrations`；Identity 嵌入模块只通过宿主 migration registrar 提交 source-owned migration。
- [x] Identity 的持久化 DDL/DML 优先使用 `github.com/domainry/domainry-orm`；ORM 无等价能力时，必须在代码旁写明原因并补齐 SQLite、MySQL、PostgreSQL 方言测试。
- [x] 可集合化的数据库写入必须批量执行并遵守方言参数上限；允许在内存中组装批次，不允许按记录逐条发 DDL/DML。
- [x] 严格按第 10 节依赖顺序开发；同一编号下的存储与 registry 子阶段允许交叉，但没有上游验收证据不得接入启动链路。兼容代码只在明确的过渡阶段存在。
- [x] 不把本次重构扩大成认证、目录、组织、审计、访问评审或整个角色版本模型的重写。
- [x] 当前只执行 0.2 的 standalone 纵向切片。第 3-9 节是后续完整重构 backlog，不是首轮 SaaS 原型的验收门槛。

### 0.1 今天讨论结论的覆盖索引

| 今天确认的问题 | 本文档中的最终落点 |
| --- | --- |
| Runtime 里的接口是否都校验权限 | 不是“所有接口都查角色 Permission”；所有入口必须注册授权策略。业务/管理 Action 校验功能权限，匿名协议、本人能力、服务身份和运维入口走各自显式策略，见 1.2、B1、B2、D2 |
| module 贡献的 surface 是否校验 | 当前 Runtime 已在 `authorizeModuleHTTPRequest` 校验 `Permission/AnyPermissions`，但没有把所有 module 权限自动同步到 Identity；目标是从现有 `modulehttp.Surface` 的同一 source manifest 投影 Action、owned PermissionDefinition 和 host gate，见 B4 及模块 SOP |
| 管理端是不是同一套实体增删改查逻辑 | 是。Identity 管理资源也建立 create/read/update/delete 和独立业务命令 Action；当前粗粒度 `*.write` 需要受控迁移，见 1.3、B2 |
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
  -> 角色沿用现有 RoleSchema 正常配置和发布流程
  -> Identity 自己的管理接口按该角色 Permission 返回 2xx/403
```

第一阶段范围：

- [x] 只选择 Identity 自有的角色管理、功能权限管理两组管理接口作为代表切片；先把 list/get、现有 authoring/validate/publish 或写操作的真实 route matrix 梳理正确，不先改完整个平台 vocabulary。
- [x] 定义最小 Action 声明字段：stable ActionKey、capability/operation/label、Method+router template、可选管理页面、authorization strategy、required/owned Permission 和现有 governance。
- [x] Action 声明只在代码和 Identity 进程内 registry；不新增 Action 表。
- [x] 实现 `_identity_permissions` current storage 与 standalone 启动 reconcile，只接入本切片 owned permissions。
- [x] `GET /identity/permissions` 以 DB PermissionDefinition 为配置真相，并从当前 Identity ActionRegistry 临时投影 Method/URL/page usages；usage 不落库。
- [ ] 复用现有 `frontend/identity-admin` 角色页和 RoleSchema change-plan/publish API，先把功能权限区域改成面向用户的 capability/operation 视图，底层 key 只作为高级详情。（视图已完成；仓库没有文档所称的 standalone change-plan/publish 后端路由，见第 12 节缺口证据。）
- [x] 使用现有 Vite `/api -> http://127.0.0.1:8081` 代理连接 standalone Identity；不为原型另造 mock backend 或 Runtime 中转层。
- [x] 旧 AuthorizationCatalog、application registration 和其兼容代码先保留，确保 standalone 登录/SDK discovery 不被首轮存储拆分阻塞。
- [x] Notification、Audit、Runtime ObjectSchema、remote module reconcile、Catalog 删除、`_identity_applications`、全 permission vocabulary 迁移全部延后到界面和 API 模型确认之后。

第一阶段只保留最小验证：

- [x] standalone Identity 能启动，Identity Admin 能登录并读取真实 `/identity/permissions`。
- [x] 空数据库启动后，本切片 Permission 自动出现；重复启动不重复；数据库能看到 current rows。
- [ ] 角色页面能按“角色管理/功能权限管理 -> 操作 -> Method+URL”勾选并通过现有 RoleSchema 流程保存/发布。（展示与勾选已通过真实页面验收；保存/发布未通过。）
- [x] 使用两个测试角色验证一个允许、一个拒绝的 Identity 管理接口，结果分别为成功和 403。
- [ ] 重启后 PermissionDefinition 和角色配置仍存在。（PermissionDefinition 与管理员 `enabled` 决策已验证；尚无法发布一份新的 RoleSchema 权限配置，因此不能把复合项勾选。）
- [x] 后端切片测试、前端相关单测和前端 build 通过。

本切片验证通过后，先让用户确认页面信息架构、Action/Permission 粒度、接口 DTO 和配置流程，再进入完整 Batch B、其它 Identity 管理资源以及 module SOP；首轮不以全仓 `go test ./...`、三方言、所有授权策略或所有 module E2E 作为阻塞条件。

## 1. 已确定的最终模型

后续实现不得再并行引入另一套权限概念。唯一链路是：

```text
代码/元数据的一份 source-owned Action manifest
  -> ActionDefinition.AuthorizationStrategy + owned/referenced Permissions + URL/页面 bindings
  -> 启动或元数据激活时同步 owned PermissionDefinitions 到 _identity_permissions
  -> ActionRegistry 投影 URL/页面配置树，Identity 从 DB 加载 Permission current snapshot
  -> 管理员按“能力/页面操作/URL”勾选，系统写入 RoleSchema.Permissions 和既有 data/field policy
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
- Permission 是角色可选择的能力键。默认一个可授权 Action 定义一个同 key Permission；只有代码显式声明复用时，多个 Action 才共享一个 Permission。
- 每个 active PermissionDefinition 必须来自一个代码/元数据 canonical owner 的 owned definition，或是明确列出的保留策略能力（例如 `workspace.admin`）；角色引用、前端菜单和历史数据库数据都不能成为定义源。
- Action 对 Permission 的引用和 Permission 的 canonical definition 分开：引用方不取得定义所有权，也不能覆盖标签、状态或 owner。
- 每个 Permission 只有一个 canonical owner；不同 owner 定义同一个 key 时，即使字段暂时相同也拒绝装配，避免以后产生双重 authority。
- PermissionDefinition 是 current configuration，不做发布版本，不新增 permission revision/publication 页面。`definition_hash` 和同步 snapshot hash 只用于幂等与并发控制，不是业务版本。
- RoleSchema 的 `Permissions []string` 继续作为角色功能权限配置的唯一真相，不新增 role-permission 中间表。
- 权限同步只增加“可选择项”，绝不自动授予普通角色；默认/系统角色的授权仍由明确 seed 或受审计的 RoleSchema 迁移完成。
- Action 与 Permission/URL/页面的绑定由当前 ActionRegistry 实时投影；不新增 `_identity_permission_usages`，也不再把 `ActionUsages` 塞进持久化 PermissionDefinition。
- Runtime ObjectSchema 继续拥有字段、引用、facts 和对象生命周期，不新增 `_identity_permission_resources`。
- `resource_key`/`action_key` 是 Permission 的稳定展示和分组信息，不是 Identity 对 ObjectSchema/URL 的复制 authority。
- 角色配置 UI 默认不暴露 `resource/action/data scope` 内部术语。管理员看到“客户管理/编辑”“PATCH /objects/customer/records/{recordID}”；保存时系统编译为 stable permission keys 以及现有 `RoleSchema.DataPermissions`/`FieldPermissions`。高级治理页可以展示底层 key，但不得要求普通配置者手工拼装。
- `public`/`tenant-admin`/`ops` exposure 只决定入口挂载位置，不代表已授权；授权仍由 Action 的 authorization strategy 决定。
- `workspace.admin` 是保留的 workspace/tenant-admin 功能权限 wildcard，不再依赖 catalog 展开；它不能自动取得 ops、service protocol 或跨 workspace 能力。
- `*`、`<resource>.*` 若继续兼容，只作为受控的系统策略表达式，不作为普通 PermissionDefinition 或普通角色页面可选项。
- 判定顺序固定为：Action/策略存在 -> 身份类型满足 -> 所引用 Permission active+enabled -> 角色/permission set/wildcard grant -> deny guardrail -> Runtime 数据/字段/引用/导出策略。
- 因此即使角色有 `workspace.admin`，被全局 disabled/retired 的 Action Permission 仍不执行；deny guardrail 也继续优先于正向 grant。
- 未注册 Action、未知 Permission、已停用 Permission、已退役 Permission均 fail closed。
- 请求热路径不逐次查询数据库或解析 JSON。ActionRegistry 和数据库 Permission current snapshot 在启动/revision 变化时编译成不可变 endpoint resolver 与 required-permission map并原子替换。

### 1.2 “所有接口都受控”的准确含义

不是每条 HTTP 路由都需要数据库中的角色 Permission。每条 HTTP/RPC/job/agent/module 入口都必须进入入口清单，并显式属于以下一种授权策略；不得靠“没有 wrapper”隐式放行：

| 策略 | 典型入口 | 是否生成角色 Permission |
| --- | --- | --- |
| `anonymous_protocol` | login、OIDC discovery/JWKS、provider callback、health/probe | 否，必须显式 allowlist |
| `authenticated_principal` | current session、effective menus、只需要已登录主体的能力 | 否 |
| `self_or_permission` | 用户读取本人资料，否则要求管理权限 | 管理分支生成/引用 Permission |
| `service_identity` | SDK application token、Runtime reconcile、内部 projection | 否，校验 application credential/audience/source scope |
| `static_permissions_all` | 同时要求多个固定管理权限 | 是 |
| `static_permissions_any` | 固定权限任一满足 | 是 |
| `dynamic_permission_resolver` | `/objects/{objectKey}`、owner handler policy | 运行时解析到具体 Action/Permission，并要求该 Permission 已初始化 |
| `operations_identity` | portability、底层运维控制 | 使用独立 ops credential/permission；`workspace.admin` 不越权 |

功能权限的最终执行点是 Action 所属边界：Identity 自有 Action 在 Identity 校验，Runtime 自有 Action 在 Runtime 校验，module Action 由 host 做公共门禁且 module application service 保留领域内最终校验。不是把 Identity 的所有接口转发给 Runtime 再校验。

### 1.3 管理端 CRUD 和语义 Action 规则

- 每个管理资源先定义稳定 resource key，再定义 `create/read/update/delete`；实际不支持的操作必须在资源能力中显式标记 unsupported，不能靠缺路由猜测。
- list/get/search/versions 等只读 URL 可以复用该资源的 `.read` Permission，但各自仍有独立 Action key 和 URL binding。
- create/update/delete 默认使用各自同名 Permission，不再长期共用一个粗粒度 `.write`。
- disable/enable/unlock/force_logout/assign/revoke/approve/reject/export 等不是 CRUD 的命令，定义语义 Action；是否复用 Permission 必须在定义旁明确，不按 HTTP method 猜。
- Identity 当前的 `identity.users.write`、`identity.roles.write`、`identity.menus.write` 等是兼容来源，不是最终粒度。迁移时为现有角色创建受审计的新 RoleSchema 版本，把 broad write 展开为保持原权限范围所需的 granular keys；不原地篡改历史版本。
- 零停机切换若需要短期 alias，只允许代码中的明确迁移映射；alias 不新增表，不出现在新角色可选列表，完成角色迁移后删除并将旧 Permission retired。
- key 命名使用稳定语义而非 URL：例如 `identity.users.list`/`identity.users.get` 两个 Action 都可显式引用 `identity.users.read`，而 create/update/delete 分别引用 `identity.users.create`、`identity.users.update`、`identity.users.delete`；特殊命令使用 `identity.users.disable` 之类语义 key。
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
- Identity 的 `registerAuditRoutes` 当前虽然读取 Audit `modulehttp.Surface`，实际却统一包成 `workspace.admin`，没有按 route 自己的 Permission/AnyPermissions 执行；这是 module surface 统一改造必须覆盖的现存偏差。
- `principal_resolver.go`、SDK binding 和 browser application registration 仍读取/发布 AuthorizationCatalog；两张 catalog 表现在不能直接删除。

## 2. 数据表处置清单

### 2.1 新增

- [x] 新增 `_identity_permissions`，保存当前、可动态管理的 PermissionDefinition。
- [ ] 后续新增 `_identity_applications`，单独保存应用身份、redirect URLs 和状态，不再借授权 catalog 保存应用注册信息。

`_identity_permissions` 固定字段：

| 字段 | 规则 |
| --- | --- |
| `id` | 稳定行 ID |
| `workspace_id` | workspace 隔离 |
| `permission_key` | workspace 内唯一，RoleSchema 存的就是此键 |
| `resource_key` | 管理页面分组，不是元数据资源副本 |
| `action_key` | 展示动作，如 create/read/approve |
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

- [ ] 删除 `_identity_authorization_catalogs`。
- [ ] 删除 `_identity_authorization_catalog_revisions`。
- [ ] 删除两张表对应的 store、repository、schema ownership、portability spec、index、迁移测试和 API 测试。
- [ ] 删除 Runtime catalog publisher、SDK catalog publish/resolve 合约及 Identity catalog JSON 热路径。

删除前置条件：Permission 已完成回填；应用 redirect 已迁移到 `_identity_applications`；Runtime/SDK 已完成新合约切换；AccessBundle 不再读取 catalog。

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
- [x] users、departments、workforce、menus、credentials、MFA、sessions、external accounts、events、access reviews：不因本次重构改变表职责。

## 3. Batch A：PermissionDefinition 存储与接入

目标：先提供 current PermissionDefinition 的正式存储/reconcile 能力；A0-A3 不改变现有 Action/catalog 对外合约。启动接入 A4-A6 必须等待 B1-B2 的 canonical Action source 完成，禁止把现有“角色引用反向补 Permission”的投影固化进新表。

### A0. 基线与保护测试

- [ ] 固化现有 Identity 平台权限 key 清单、元数据对象 CRUD 投影和业务 Action `RequiresPermission` 投影；这些测试记录旧行为但不把旧 read/write 粒度或 system_object 跳过规则当成目标。
- [ ] 固化 RoleSchema `Permissions []string` 的保存、校验、版本发布和角色授权行为。
- [ ] 固化 permission set/group 扩展、deny guardrail、`workspace.admin` 与 ops exact-permission 的当前优先级。
- [ ] 固化 Identity 全入口清单：identity management、auth/browser、Remote SDK、audit surface、portability ops、health、直接注册 tenant-admin 路由。
- [ ] 固化 Runtime 的 `EndpointContracts`、business ActionCatalog、`modulehttp.Surface` 路由清单及当前 host module permission gate。
- [ ] 固化 embedded module 使用宿主 DB、transaction、dialect、migration lock 和 `_schema_migrations` 的测试。
- [ ] 标注当前 catalog 依赖测试为 compatibility，避免误认为最终设计。

### A1. Schema 和迁移

- [ ] 在 Identity owned schema 中定义 `_identity_permissions` 全部字段、唯一约束和必要索引。
- [ ] 添加 `(workspace_id, permission_key)` 唯一索引。
- [ ] 添加 `(workspace_id, definition_status, enabled)` 查询索引。
- [ ] 添加 `(workspace_id, source_owner)` 同步索引。
- [ ] 将表加入 schema ownership 和 portability specs。
- [ ] Standalone 模式通过 Identity 自有 migration registrar 建表。
- [ ] Embedded 模式只提交 source-owned migration 给宿主 registrar，不创建第二本 migration ledger。
- [ ] 增加 SQLite、MySQL、PostgreSQL schema rendering/contract 测试。

### A2. Domain 和 Repository 合约

- [ ] 扩展 PermissionDefinition，使持久化字段与当前展示/Action 元数据字段职责明确；删除或停用 `ActionUsages` 的持久化语义。
- [ ] 新增独立的 `IdentityPermissionDefinitionRepository`，不强迫所有既有 `IdentityRepository` 测试桩一次性实现新方法。
- [ ] 定义按 workspace 列出 current PermissionDefinitions 的接口。
- [ ] 定义按 `source_owner` 提交完整 snapshot 的 reconcile 接口，包含 `previous_snapshot_hash`、新 snapshot hash 和 receipt。
- [ ] 定义管理员 enable/disable 所需接口，但实际管理 API 放到 Batch F 开放。
- [ ] 定义并测试 canonical definition hash；hash 不包含 `enabled`、数据库 ID 和时间戳。
- [ ] 定义并测试 canonical source snapshot hash；输入排序无关，相同集合重复同步 hash 相同。
- [ ] 把现有 `IdentityPermissionDefinition` 中 risk/approval/assurance/ActionUsages 等 Action 属性移出持久化模型；API 兼容投影与持久化 entity 分开。

### A3. ORM 持久化实现

- [ ] 使用 domainry-orm 实现 workspace-scoped list/get/upsert/reconcile。
- [ ] reconcile 新定义时插入 `active + enabled=true`。
- [ ] reconcile 已有定义时更新 source-controlled 字段，但保留管理员设置的 `enabled`。
- [ ] 同一个 `source_owner` 中本轮缺失的 key 标记为 `retired`，不物理删除。
- [ ] 已退役 key 被同 owner 重新定义时恢复为 `active`，继续保留原 `enabled` 决策。
- [ ] 不同 canonical owner 抢占同一 `permission_key` 时返回明确冲突错误并回滚整个事务。
- [ ] `previous_snapshot_hash` 不匹配时拒绝 stale reconcile，旧 Runtime/重试请求不得覆盖更新后的定义集合。
- [ ] 只引用现有 Permission 的 Action 不写 Permission 行，也不会因自己的 snapshot 缺失而 retire 别人的 Permission。
- [ ] 所有读写都使用 request/assembly 传入的 transaction executor，不绕过宿主事务边界。
- [ ] 覆盖 workspace 隔离、幂等、退役、恢复、owner 冲突、stale snapshot、引用不夺权、enabled 保留和事务回滚测试。

### A4. 启动和元数据激活同步

- [ ] 代码 Action contract 同时表达 required permission references 与本 owner 的 PermissionDefinitions；先合并完整 ActionRegistry，再只提取 owned definitions 同步。
- [ ] Identity standalone 启动时同步 Identity built-in 权限；不得继续依赖 `generatedGlobalPermissionKeys` 与角色引用拼成内存 catalog。
- [ ] workspace provisioning 时同步 Identity built-in 权限，保证新 workspace 不需要先访问权限页才初始化。
- [ ] Runtime 启动/metadata activation 时同步项目 Object、business Action、Runtime built-in 与 module owner 的权限；embedded 走 host transaction，remote 走 SDK service credential。
- [ ] 第一次升级时将当前代码/元数据可推导出的权限回填到 `_identity_permissions`。
- [ ] 删除“从 RoleSchema 中发现未知 key 就生成 PermissionDefinition”的逻辑；角色只能引用定义，永远不能反向创造定义。
- [ ] 角色中历史存在、但当前代码无法识别的 key 标记 unknown，不静默删除、不授权，并为后续人工修复生成治理结果。
- [ ] Identity metadata reload observer 改为可返回 error，并将流程调整为“候选 snapshot -> Action/Permission 校验与 reconcile -> 原子替换 runtime snapshot”；失败继续使用旧 snapshot，不得先 Apply 再报错。
- [ ] 数据库 active/enabled PermissionDefinitions 加载为不可变内存快照；内存只做缓存，不再是定义真相。
- [ ] restart 后从数据库恢复管理员 `enabled` 状态，代码同步不得把它重置。
- [ ] 同步成功记录 source owner、snapshot hash、增加/更新/retire 数量与 request ID 的审计/日志证据，但不创建业务发布版本。

### A5. 读取和角色校验切换

- [ ] `GET /identity/permissions` 改读当前 workspace 数据库定义，并返回 active/disabled/retired 状态。
- [ ] 普通角色新增/修改只能选择存在、active、enabled 的 permission key。
- [ ] 已经被角色引用的 disabled/retired key 继续可查询并带状态警告，不能再新增选择。
- [ ] permission set/group 中的 permission keys 使用同样的存在、active、enabled 校验；deny guardrail 可以继续引用 exact/wildcard deny 表达式。
- [ ] principal 构建时在 direct role 与 permission set 展开之后统一过滤 unknown/disabled/retired keys，再执行 guardrail；不能只在保存角色时检查。
- [ ] 现有角色校验、effective access、governance report 使用同一个 PermissionDefinition snapshot。
- [ ] AuthorizationRevision 的计算输入加入实际生效的 PermissionDefinition snapshot/state fingerprint；不必先增加全局 revision 表，但 disabled/retired 变化必须让新 principal/bundle revision 改变。
- [ ] 保持当前前端 `permissionsApi.catalog` 返回结构的兼容字段，新增状态字段采用向后兼容方式。

### A6. Batch A 退出条件

- [ ] 权限行在系统启动后自动出现于数据库，无需手工 seed SQL。
- [ ] 对同一份代码/元数据重复启动不产生重复行。
- [ ] 管理员停用状态能够跨重启保留。
- [ ] 删除代码定义后，权限变为 retired 而不是消失或被物理删除。
- [ ] built-in Identity 权限、对象默认权限、业务 Action 权限均能被角色正常选择。
- [ ] 权限同步只产生可选 Permission；除明确 seed/迁移外，没有任何普通角色被自动授予新权限。
- [ ] 角色、permission set 中的 unknown/disabled/retired 权限不会进入新 AccessBundle。
- [ ] Identity 单元测试、数据库测试、assembly 测试全部通过。

## 4. Batch B：统一 ActionDefinition 和内置 URL 校验

目标：消除“路由表一份、权限包装器一份、Permission 生成又一份”的重复定义。

### B1. Action 合约

- [ ] 在 `domainry-foundation` 的 deployment-neutral shared contract 层定义规范化 `ActionDefinition`/authorization strategy；Identity 不能依赖 Runtime，Identity SDK 只承载 reconcile/application wire contract，不能为 Runtime、Identity、module 各建一个不兼容模型。
- [ ] `ActionDefinition` 固定包含 stable key、owner、source kind、capability/operation/label、exposure、authorization strategy、HTTP/页面/非 HTTP bindings、required permissions、grantable、risk/assurance/approval/idempotency/audit/lifecycle。
- [ ] authorization strategy 支持 anonymous protocol、authenticated principal、self-or-permission、service identity、static all、static any、dynamic resolver 和 operations identity；不能只支持 `RequiredPermissions` 一个字段。
- [ ] 定义 owned PermissionDefinitions 与 required permission references 的明确结构；默认同 key，显式 reuse 才允许多 Action 共用 Permission。
- [ ] 定义 `ActionRegistry`：注册、冻结、按 action key 和 method/path 解析、动态 resolver、重复冲突检查、permission owner/reference 校验、usage 反向投影。
- [ ] 适配而不是重复定义现有资产：Runtime `ActionSchema`、`RuntimeEndpointContractV1.PermissionPolicyRef`、Foundation `modulehttp.Route`、Identity route definitions 都投影到同一个规范化 registry。
- [ ] Runtime endpoint contract 当前由 generator 生成；Action 接入必须修改 source/generator 和 contract tests，禁止直接手改生成文件形成第四份 authority。
- [ ] HTTP route 只保存 method/path binding；非 HTTP Action 可没有 URL。
- [ ] Action key 和 Permission key 分开；允许多个 Action 引用同一 Permission。
- [ ] Action manifest 只存在于代码/元数据和冻结后的运行时 registry；不得把 handler/function pointer 或 Action 安全定义复制进 Identity 持久化模型。
- [ ] 一个 HTTP Action 必须含 method + router template；配置树显示具体 `display_route_template`，不能把原始动态 `/objects/{objectKey}` wildcard 暴露成可授权项。
- [ ] registry 在服务 ready 前冻结，运行中只读。
- [ ] 普通 HTTP handler 不再自行解释 permission string；公共 middleware 必须先从已编译 snapshot 解析 Action，再执行声明的 authorization strategy。

### B2. Identity 内置 surface 改造

- [ ] 生成并评审 Identity 完整 route/action matrix，覆盖 `identity_routes.go`、`auth_routes.go`、browser gateway、Remote SDK、audit module routes、portability ops、health/probes、server 直接注册路由和未来 module surfaces。
- [ ] Identity authoring capability 中的 `ConfigurationRoutes`、`ValidationEndpoint`、`Execution.PermissionModel` 也必须由/校验到同一 matrix，不能让 capability contract 继续维护另一份 URL/permission truth。
- [ ] matrix 每行固定记录 owner、method/path、action key、authorization strategy、permission all/any/dynamic resolver、exposure 和 audit/governance；不允许只有 URL 没有策略。
- [ ] matrix 同时记录 capability/operation/label 和 `/admin/...` 页面 binding；`identity_admin_routes.go`、菜单可见性和后端 route gate 都从 matrix 投影。
- [ ] 为 users、departments、workforce、roles、role assignments、role requests、menus、role menus、permissions、data scopes、field permissions、security、access reviews、governance 等管理资源定义 CRUD/语义 Actions。
- [ ] list/get/search/versions 统一引用资源 read；create/update/delete 分离；disable/enable/unlock/force_logout/assign/revoke/approve/reject 等使用语义 Action。
- [ ] 盘点现有 `Authenticated(...)` 管理路由，逐条明确是 principal-only、self、dynamic owner policy 还是遗漏 Permission；不允许把“已登录”长期当成管理授权。
- [ ] 将 route 注册和 authorization middleware 绑定到同一个 ActionDefinition，禁止手写第二份 permission string。
- [ ] 保留经评审的 self-or-permission 语义，将它表达成 Action policy，不在 handler 里另造授权逻辑。
- [ ] Identity 内置 PermissionDefinitions 由同一 matrix 中 canonical-owned permission 定义生成并 reconcile；角色管理 list/get/create/update/delete/assign/configure 等 Action 可共享或拥有稳定 Permission，但 URL/Action 本身不落 Identity DB。
- [ ] 非 HTTP 的内置管理能力同样注册 Action，不用虚构 URL。
- [ ] 菜单可见性和 `AdminRouteRequiredPermissions` 改为从同一 ActionRegistry/route matrix 投影，删除前端菜单、后端路由各维护一份 permission mapping 的状态。
- [ ] auth discovery/callback/login、Remote SDK service endpoints、portability ops 明确保留各自协议身份策略，不为它们伪造普通角色 Permission。

### B2.1 现有 broad permission 迁移

- [ ] 先生成完整 permission vocabulary 审计，识别粗粒度 key、命名不一致和语义重复，例如 `identity.permission.configure` 与 `identity.permissions.write`、`identity.audit.view` 与 Audit owner 权限；逐项确定唯一 canonical key/owner。
- [ ] 建立旧 key 到新 granular keys 的完整映射，至少覆盖 users/departments/workforce/roles/menus/permissions/data scopes/field permissions/security；映射按当前所有实际路由权限语义生成，不能只做字符串替换。
- [ ] read key 若仍与目标 read 相同可原样保留；每个 `*.write` 按它今天实际允许的 create/update/delete/semantic commands 展开，确保迁移后既不扩权也不丢权。
- [ ] 对当前 published RoleSchema、permission sets 和系统 seed 创建可审计迁移；RoleSchema 历史版本不可原地改写。
- [ ] 同步更新 `IdentityPlatformPermissionKeys`、admin route/menu guards、authoring capability `Permissions/PermissionModel`、默认角色 seed 和前端 route guard；迁移完成后删除旧 broad key 的生产引用。
- [ ] 迁移期间的新角色页面只展示新 granular keys；必要的 legacy alias 只为旧 bundle/role 过渡服务。
- [ ] 没有任何 active RoleSchema/permission set 再引用旧 broad key 后，将旧 PermissionDefinition retired，并删除 alias evaluator。
- [ ] 增加迁移前后 effective access 等价测试，以及 create/update/delete 能独立授权的测试。

### B3. 默认对象 Action

- [ ] 提供唯一的 `DefaultActionsForObject(ObjectSchema)` 规则。
- [ ] 每个成功激活的 ObjectSchema 必须有显式 capability set；普通可变对象默认生成 create/read/update/delete，存在导出 surface 时生成 export。
- [ ] 只按对象声明的 immutable/read-only/no-delete/no-export 等实际能力裁剪，不生成无法调用的操作；没有能力声明时使用标准 CRUD 默认值。
- [ ] `system_object` 只表示所有权，不再作为跳过权限的理由；只要它是已激活 ObjectSchema，就按其 capability set 生成 Action/Permission。
- [ ] 内部 persistence table 若不是 ObjectSchema surface，不生成 Action/Permission。
- [ ] 默认 Action 同时产生 stable ActionDefinition 与 owned PermissionDefinition，Permission 自动进入 DB 但不自动进入任何普通角色。
- [ ] 通用 router 仍注册 `/objects/{objectKey}/records` 等模板；metadata activation 按每个 active ObjectSchema 生成具体运行时 Action，例如 customer list/get/create/update/delete，dynamic resolver 绑定 `objectKey=customer`，配置投影显示具体 URL。
- [ ] 请求匹配通用 router 后提取 `objectKey` 和操作，dynamic resolver 必须解析到该对象的具体 `action_key`；角色页绝不提供“全部 objectKey”泛化授权项。
- [ ] metadata candidate 的默认 Action/Permission 在激活前完成校验和 reconcile；失败不发布 ObjectSchema。
- [ ] 删除 Identity 与 Runtime 现在不一致的两套 CRUD 推导逻辑。

### B4. Module surface

- [ ] 严格执行 [module-authorization-onboarding-sop.md](module-authorization-onboarding-sop.md)；未通过 source manifest、reconcile 和覆盖测试的 module 不得 ready。
- [ ] 以现有 `modulehttp.Surface`/`modulehttp.Route` 为落点补齐 stable Action key、capability/operation/label、页面 binding、authorization strategy 和 owned/reused Permission 声明，或提供无损 adapter；不另造与 modulehttp 并行的 surface 注册体系。
- [ ] module 只能维护一份 source-owned Action manifest；route mounting、host gate、OpenAPI、Identity reconcile payload 和配置树都必须从它投影，禁止 module `Catalog()`、Runtime hardcode、surface Permission 三份手写。
- [ ] Notification、Audit 及后续 module surface 在装配时注册自己的 Actions。
- [ ] 先以 Notification 作为首个 SOP 验证：收敛 `ProductRoutes()` 的 dotted permissions、Notification Catalog/internal resource-action 和 Runtime Notification catalog hardcode，逐项确定 canonical action key 与 permission key 并提供兼容迁移。
- [ ] 删除 Runtime `identity_catalog.go` 中 Notification 专用权限硬编码；所有 module 都从各自 surface/action contribution 泛化派生。
- [ ] 宿主合并所有 Action contributions 并校验后，再按 owner reconcile owned PermissionDefinitions；冲突或未知引用时拒绝 ready，成功 receipt 前不得挂载/激活新 surface。
- [ ] module 的 permission canonical owner 保持 source module，不转移给 host/Identity。
- [ ] embedded 模式由 host 在同一 DB/transaction/migration 边界装配和同步；standalone/remote module 由 owner 使用 service credential 同步，语义相同。
- [ ] host 的通用 authentication/permission/governance gate 与 module application service 的领域内校验都保留，避免 transport gate 成为唯一防线。
- [ ] module 升级/卸载时保留 stable action key；URL 改动只更新 binding，删除的 Action/Permission 先 retired，不能重写角色；permission 重命名必须提供显式角色/permission-set 等价迁移。

### B5. 覆盖与退出条件

- [ ] 增加测试：每条受保护 Identity route 恰好映射一个 ActionDefinition。
- [ ] 增加测试：所有 Identity route 都有且只有一个显式 authorization strategy；受保护 route 未注册、策略缺失、引用未知/disabled/retired Permission 时装配或请求失败。
- [ ] 增加测试：public route 必须显式标记 public，不能因漏注册而放行。
- [ ] 增加测试：module-contributed surface 一定经过同一校验。
- [ ] 增加测试：self、service credential、dynamic object resolver、ops exact permission 不会被错误地折叠成普通静态角色权限。
- [ ] 删除已被 registry 替代的散落权限常量/路由 permission wrapper，确有非路由用途的常量必须标明 owner。

## 5. Batch C：应用注册拆分和 Catalog 降级为兼容层

### C1. `_identity_applications`

- [ ] 定义 application key、workspace、redirect URLs、status、created/updated timestamps，并落实 `(workspace_id, application_key)` 唯一约束。
- [ ] 使用 domainry-orm 实现 application registration repository。
- [ ] redirect URL 校验和 application existence 检查改读 `_identity_applications`。
- [ ] service credential secret 继续留在既有 secret/config 边界，不复制到此表。
- [ ] 将现有 catalog application 数据幂等回填到新表。
- [ ] Identity browser application 启动改为 register current application，不再发布空 AuthorizationCatalog。
- [ ] AuthHandler 的 `ApplicationRegistered` 判断改读 application repository，不再用 `Catalog().CurrentRevision()` 判断应用是否存在。

### C2. Catalog compatibility adapter

- [ ] 保留旧 Catalog Publish API 作为短期适配器，不再把 JSON 当授权真相。
- [ ] 旧 catalog 中 Actions 翻译为 Permission reconcile 请求和运行时 Action compatibility projection。
- [ ] 旧 catalog key 已有正式 owner 时 compatibility adapter 只做引用校验、不写定义；仅对尚无正式定义的 key 使用隔离的 `compat:application:<key>` owner，不能覆盖 Identity/module 正式 canonical owner。
- [ ] 旧 catalog 中 application redirects 翻译为 application registration。
- [ ] 返回兼容 receipt，但明确标记 catalog revision 已弃用。
- [ ] 新 AccessBundle 解析不再要求 catalog 已发布。
- [ ] 删除 principal resolver 中的 `identity.catalog_not_published` 硬依赖。
- [ ] 删除 catalog 对 grants、data/field/reference/export policy 的二次裁剪。
- [ ] `workspace.admin` 改为保留 wildcard grant，不枚举 catalog action。

### C3. 退出条件

- [ ] Identity 在没有 catalog JSON 的情况下可完成登录、角色解析和 AccessBundle 生成。
- [ ] redirect 校验完全依赖 `_identity_applications`。
- [ ] compatibility Publish 可重复调用且不会覆盖 Permission 管理员开关。
- [ ] catalog 仅剩兼容入口，不在请求授权热路径中。

## 6. Batch D：SDK 与 Runtime 切换

### D1. SDK 合约

- [ ] 增加按 workspace + source owner 提交完整 PermissionDefinition snapshot 的批量 reconcile 合约，包含 previous/new snapshot hash、definition counts 和 receipt。
- [ ] 增加 application registration 合约。
- [ ] 增加 authorization revision / snapshot 合约，替换 CatalogRevision 语义。
- [ ] local binding 与 remote HTTP binding 行为、错误码和事务语义一致。
- [ ] 未知 owner、定义冲突、stale activation receipt 返回可定位错误。
- [ ] remote reconcile 使用 application service credential，并校验 workspace/application/source owner scope；普通用户 token 不能发布代码权限定义。
- [ ] reconcile API 管定义，角色配置 API 管授权选择，两者严格分开。

### D2. Runtime ActionRegistry

- [ ] Runtime 从 Object 默认 Actions、authored business Actions、`EndpointContracts`、内置 Runtime surface 和 `modulehttp.Surface` contributions 构建唯一规范化 registry。
- [ ] `owner_handler_policy:*` 路由必须注册 dynamic permission resolver，运行时由 path/object/action 解析具体 key；静态 `RequiredPermissions` 为空不等于无需权限。
- [ ] anonymous、service protocol、principal-only、ops 路由必须按 1.2 显式分类，不为追求“每路由一 Permission”制造错误权限。
- [ ] Runtime 启动时先校验 registry，再调用 Identity reconcile，收到成功 receipt 后才 ready。
- [ ] 元数据更新采用“构建候选 registry -> reconcile -> 原子激活”顺序，失败继续使用旧 snapshot。
- [ ] Runtime 直接用当前 ObjectSchema 校验 data/field/reference/export policy，不再要求 Identity 镜像资源细节。
- [ ] Identity 对 data/field/reference/export 配置做结构和 permission-key 校验；Runtime 在候选 metadata/schema 上做对象、字段、关系存在性及执行语义的最终校验。
- [ ] 管理端资源/字段选择数据来自 Runtime 当前 metadata API，不从 `_identity_permissions.resource_key` 反建 ObjectSchema。
- [ ] 请求按 resolved Action.AuthorizationStrategy 执行校验；角色授权分支检查 required permissions 与 AccessBundle，不存在 Action 或 required Permission 时 fail closed。
- [ ] URL、RPC、job/agent 等不同入口使用同一 Action 语义。

### D3. revision 与缓存

- [ ] Identity 的 AuthorizationRevision 覆盖 user/workforce/assignments/roles/permission sets/guardrails，以及过滤后的 active+enabled Permission state fingerprint；可以沿用当前确定性 hash，不为此强制新增 revision 表。
- [ ] Runtime 维护 Metadata/ActionRegistry revision。
- [ ] AccessBundle/cache key 使用 subject/workspace + AuthorizationRevision；需要对象结构时再组合 MetadataRevision。
- [ ] 不在每个请求中查 `_identity_permissions`，也不解析 catalog JSON。
- [ ] 权限停用后，新解析 principal/bundle revision 必须变化；Runtime 对已有缓存按 revision/最大陈旧窗口失效，不能让旧自包含权限无限有效。
- [ ] 明确 bearer/session/worker reauthorization 的最大陈旧窗口和强制刷新路径，测试 disabled Permission 在窗口内收敛。

### D4. 跨部署验收

- [ ] embedded direct binding 端到端测试通过。
- [ ] remote SDK + real Identity HTTP server 合同测试通过。
- [ ] Runtime 内置 surface、Identity 内置 surface、metadata Action、module surface 均有授权正反例。
- [ ] anonymous/authenticated-self/service/dynamic/ops/static-all/static-any 每种策略都有正反例和越权回归测试。
- [ ] SQLite、MySQL、PostgreSQL 关键 schema/repository 合同通过。

## 7. Batch E：彻底删除 Authorization Catalog

- [ ] 发布升级前检查：所有 workspace 已有 PermissionDefinition 和 Application 回填结果。
- [ ] 删除 Identity Catalog Publish/Get/Resolve API 和 handler。
- [ ] 删除 SDK catalog DTO、client、local/remote binding。
- [ ] 删除 Runtime `identity_catalog.go` publisher 和 catalog assembly dependency。
- [ ] 删除 Runtime catalog 中资源 fields/references/facts 镜像以及 Notification 专用拼装。
- [ ] 删除 `internal/infrastructure/persistence/database/identitycatalog`。
- [ ] 删除 principal resolver、binding、catalog policy 中所有 catalog 读取、展开和过滤代码。
- [ ] 删除 `_identity_authorization_catalogs` / `_identity_authorization_catalog_revisions` schema、indexes、ownership、portability specs。
- [ ] 通过宿主 migration registrar 提交 drop migration；升级测试覆盖已有数据数据库。
- [ ] 删除只验证旧 catalog 行为的测试，保留等价新链路回归测试。
- [ ] 全仓 `rg` 确认生产代码不再出现 CatalogRevision、authorization catalog store 或 catalog-not-published。

## 8. Batch F：动态管理与治理闭环

### F1. Permission 管理 API

- [ ] 增加 enable/disable API，只能改管理员控制字段，不能改 source-owned 定义字段。
- [ ] 增加审计事件：actor、workspace、permission key、before/after、reason、request ID。
- [ ] 停用后使 AuthorizationRevision 的 Permission state fingerprint 变化，并使新解析的 AccessBundle 立即移除该能力。
- [ ] 停用判定发生在 wildcard grant 之前，因此 `workspace.admin` 也不能执行被 disabled/retired 的功能；ops/service 路径按独立策略处理。
- [ ] 对 `workspace.admin`、Permission 管理和角色管理等关键能力增加最后管理员/锁死保护，避免 workspace 无人可恢复。
- [ ] retired Permission 不允许直接 enable；必须由 canonical owner 恢复定义后再启用。

### F2. 管理端页面

- [ ] 权限页直接展示数据库 current definitions，不做 permission 发布版本页。
- [ ] 按 resource/category/source 分组，显示 active/disabled/retired 和 canonical owner。
- [ ] 页面以“资源 + 动作 + 绑定入口”解释权限；URL 可用于帮助管理员理解 Action，但 URL 不是可编辑 Permission key。
- [ ] 角色页只允许勾选 active+enabled；已引用异常 key 显示修复警告。
- [ ] Action usage 通过 Action owner 的 registry query 实时展示：embedded 可直接聚合，remote 从 Runtime/module 查询；Identity 不落 usage 表，owner 不可达时明确显示 unavailable。
- [ ] 对象资源文案来自 Runtime/ObjectSchema 投影，不在 Identity 维护资源元数据副本。
- [ ] 角色权限编辑继续提交正常 RoleSchema version/change path；Permission 页面没有 draft/publish/version lifecycle。
- [ ] 前端 route guard/menu visibility 只是体验投影，数据来自同一 registry/permission API；最终授权始终以后端 owner boundary 为准。

### F3. 治理

- [ ] 报表列出仍被角色引用的 disabled/retired/unknown permission keys。
- [ ] effective-access explain 能说明 Permission 来源、角色来源、deny guardrail 和最终结果。
- [ ] access review 能看到权限状态变化，但不把 PermissionDefinition 变成版本发布实体。

## 9. 全局验收矩阵

### 功能完整性

- [ ] Identity、Runtime、module 的所有入口都在各自 owner/host 边界解析到一个显式 Action authorization strategy；不存在“漏 wrapper 就放行”的入口。
- [ ] 所有角色功能权限 Action 都检查 DB 中 current PermissionDefinition；匿名、本人、service、ops 等入口按声明的非角色策略校验，不能混为一谈。
- [ ] module 贡献的 surface 与内置 surface 使用同一注册、同步和校验机制。
- [ ] 每个成功激活的元数据 ObjectSchema 都按 capability set 初始化默认 Action 和对应 Permission，`system_object` 不再被直接跳过。
- [ ] Identity 角色管理等内置 URL 对应的 Action/Permission 会自动初始化到 DB 并可供角色选择。
- [ ] Identity 管理资源能独立配置 read/create/update/delete 和必要语义 Action；现有 broad write 权限完成等价迁移并最终 retired。
- [ ] 当前平台 permission vocabulary 中语义重复/owner 冲突的 key 已完成 canonicalization、角色等价迁移和旧 key retirement。
- [ ] 管理员能动态停用 Permission，重启后状态保持，授权立即按 revision 收敛。

### 数据一致性

- [ ] 一个 workspace 的同一 permission key 只有一行和一个 canonical owner。
- [ ] reconcile 重复执行、进程重启、metadata reload 都幂等。
- [ ] stale reconcile 被 CAS snapshot hash 拒绝；只引用 Permission 的 Action 不会取得 owner 或 retire 定义。
- [ ] 角色选择只存于 RoleSchema，不出现第二份 role-permission authority。
- [ ] retired/disabled/unknown key 不会被静默授权。
- [ ] RoleSchema 中出现的未知 key 不会反向创建 PermissionDefinition。
- [ ] Runtime ObjectSchema 不复制到 Identity 资源表。

### 工程与部署

- [ ] 所有 DML 使用 domainry-orm；必要 raw SQL 有本地原因和三方言测试。
- [ ] embedded module 与 standalone SaaS 行为一致。
- [ ] 每个数据库仍只有宿主的 `_schema_migrations`。
- [ ] migration、portability、backup/restore 覆盖新表并清理旧表。
- [ ] route/action coverage 测试覆盖 Identity 全部 route registrars、Runtime EndpointContracts 和所有 modulehttp surfaces。
- [ ] Identity、SDK、Runtime 全量测试和 lint 通过。

## 10. 开发顺序与提交边界

严格按以下顺序执行，每一项可以形成独立、可回滚的提交：

1. [ ] S0：完成 0.2 的 Identity standalone 纵向切片，实际运行后评审 UI、Action 声明和 `/identity/permissions` DTO；未确认前不向 Runtime/module 推广。
2. [ ] A0-A3：将 S0 已验证的 `_identity_permissions` schema、repository、snapshot-CAS reconcile 补齐为正式基础和必要数据库测试。
3. [ ] B1：把 S0 Action 声明提炼为 shared normalized Action contract/registry，并为现有 Runtime EndpointContract、modulehttp.Route、metadata ActionSchema 设计无损 adapter。
4. [ ] B2-B2.1：从 S0 两组接口扩大到 Identity 全 route/action matrix、内置 Action 注册、CRUD/语义 Permission 定义及 broad-key 迁移工具/测试。
5. [ ] A4-A6：完成全量 Identity 启动/workspace provisioning 同步、DB 读取、principal 过滤、RoleSchema/permission-set 校验和 assembly 测试。
6. [ ] B3-B5：统一 Object 默认 Action、module contribution、菜单投影和全入口覆盖测试；此时才执行 module SOP 和 Notification 样例。
7. [ ] C1：application registration 表、回填、browser registration 和 redirect/application lookup 切换。
8. [ ] C2-C3：catalog 退出 AccessBundle 热路径，只留 compatibility adapter。
9. [ ] D1：SDK local/remote reconcile、application、authorization snapshot 新合约。
10. [ ] D2-D4：Runtime 完整 registry、候选激活协议、revision/cache 和跨部署测试。
11. [ ] E：删除 catalog API、代码和两张 catalog 表。
12. [ ] F：Permission 开关、完整管理端页面、审计和治理闭环。

## 11. 首个开发任务

在用户确认本文档后，只开始 S0，不提前碰 Runtime、SDK/module 推广、Catalog 删除或完整 vocabulary 迁移：

- [ ] 生成角色管理和功能权限管理两组实际接口的 route/action 对照，先评审 ActionKey、能力/操作文案、Method+URL、页面和 Permission 粒度。（实现与证据已准备，等待用户评审后勾选。）
- [x] 为 `_identity_permissions` 增加满足 standalone S0 的 owned schema、必要 index 和 SQLite migration；repository 使用 domainry-orm。
- [x] 从这两组 Identity code-owned Actions 启动 reconcile PermissionDefinitions，禁止从 RoleSchema 反向补定义。
- [x] 调整 `/identity/permissions` DTO：Permission 状态来自 DB，Action/Method/URL/page usage 来自当前进程 registry，usage 不持久化。
- [ ] 调整 Identity Admin 角色权限区域，按能力/操作展示接口并沿用现有 RoleSchema change-plan/publish 流程。（能力/操作视图已完成；change-plan/publish 后端缺失，保持未勾选。）
- [x] 启动 `cmd/identity-server` 和 `frontend/identity-admin`，完成 0.2 中除 change-plan/publish 外的人工/自动验证并记录可复核的界面/API/DB 证据。
- [ ] 用户评审 UI、DTO 和权限粒度后，再决定是否扩大到全部 Identity routes。

S0 明确不新增 `_identity_actions`，不删除或升级 AuthorizationCatalog，不新增 `_identity_applications`，不接 Notification，不修改 Runtime catalog publisher，不要求 MySQL/PostgreSQL 或全仓测试先阻塞界面验证。

## 12. S0 执行证据（2026-09-01）

### 12.1 已完成实现与代码证据

- Action 单一来源：`internal/application/identity/identity_builtin_authorization_actions.go` 声明 11 条真实路由 Action、2 个 capability、4 个兼容 PermissionDefinition；`internal/application/identity/identity_action_registry.go` 在装配时拒绝重复 Action、重复 canonical owner、重复 Method+route 和未知 Permission 引用。
- current 存储：`internal/infrastructure/persistence/database/schema/identity_permissions.go` 使用 domainry-orm schema builder 定义 `_identity_permissions`、workspace 内 permission key 唯一约束、状态索引和 source owner 索引；表已加入 ownership、portability spec 和 `006_identity_authorization_permissions` migration。
- 批量 DML：`internal/infrastructure/persistence/database/identity/authorization/permission/store.go` 先以一条集合 UPDATE 标记 owner 旧集合，再按数据库 bind parameter 上限执行多行 UPSERT；只在内存中组装批次，不按 permission 逐条写 DB。冲突更新明确不覆盖 `enabled`、`id`、`created_at`。
- reconcile 语义：同 owner 完整 snapshot 使用 previous/new snapshot hash 做 CAS；首次插入 active+enabled，缺失项 retired，恢复项 active，跨 owner 冲突整事务回滚，管理员 `enabled` 决策在同步与重启后保留。
- 热路径：`internal/application/identity/identity_permission_catalog.go` 在 reconcile 后把 DB active/enabled 状态原子替换为不可变内存快照；Action gate 先检查 Permission current state，再检查角色 grant，不逐请求查 DB，unknown/disabled/retired fail closed。
- standalone 接线：`internal/transport/http/server/service.go` 只在 standalone `NewWithStore` ready 前执行 Identity built-in reconcile；deployment-neutral core 只装配 registry/service，embedded 路径未擅自执行 remote/module 推广。
- 读取投影：`GET /identity/permissions` 从 `_identity_permissions` 读取 current definition/state/hash/owner，并由当前进程 registry 投影 capability、operation、Action、Method、router template 和 page；没有 usage 表。
- 管理端：`frontend/identity-admin/src/features/org/permission-capability-view.ts` 以 `capability_key + operation_key` 聚合；`roles.tsx` 默认展示功能、操作、Method+URL 和页面入口，技术 permission key 收进详情，retired/disabled 不可选择。
- 兼容边界：旧 AuthorizationCatalog、application registration、RoleSchema `Permissions []string`、permission set/group、guardrail、data/field policy 均保留；未修改 Runtime、SDK/module 推广和 Notification。

### 12.2 自动测试证据

- `go test ./...`：通过；包含 Action route/owner 校验、SQLite reconcile/restart、角色允许/拒绝 HTTP 切片、schema/migration/portability/assembly 回归。
- `go vet ./...`：通过。
- `go test ./internal/infrastructure/persistence/database/identity/authorization/permission`：通过；SQLite、MySQL、PostgreSQL 均验证一次多行 UPSERT，且冲突部分不更新 `enabled`/`created_at`。
- `go test ./internal/infrastructure/persistence/database/identity/integrationtest`：通过；覆盖首次插入、重复幂等、retire、restore、stale CAS、owner 冲突回滚、workspace 隔离、disabled 状态重启保持。
- `npm run test:unit --workspace identity-admin`：29 个测试文件、104 个测试全部通过。
- `npm run build:identity-admin`：类型检查、品牌检查、12 条前端 route registry 检查和 Vite production build 全部通过；只有既存的大 chunk 提示，不是构建失败。

### 12.3 真实 standalone/API/DB/界面证据

- 使用临时 SQLite 启动 `cmd/identity-server`，日志显示 development listener ready；再用 Vite `/api` proxy 启动 `frontend/identity-admin`。
- 真实管理员登录成功；首次临时密码交接后重新登录进入 `/admin`，再进入 `/admin/org/roles`。
- 真实 `GET /identity/permissions` 返回 4 条 DB definition：`identity.roles.read/write`、`identity.permissions.read/write`；全部 owner=`identity:builtin`、status=`active`，live route usage 数分别为 6、2、2、1。
- SQLite 查询结果：`_identity_permissions` 行数 4、distinct permission key 数 4；唯一 migration ledger 为 `_schema_migrations`，当前 schema version 为 `006_identity_authorization_permissions`。
- 同一数据库停止并重启 standalone 后仍为 4 行，没有重复；集成测试另外证明管理员 disabled 决策不会被启动 reconcile 重置。
- 真实角色页显示“角色管理 / 功能权限管理 -> 查看 / 配置 -> Method + URL -> 页面入口”；内置 Admin 锁定，非内置 Organization administrator 可勾选，技术 key 仅在“技术详情”中显示。
- server HTTP 切片以 Admin 角色读取 `/identity/permissions` 得到 200；改用没有 `identity.permissions.read` 的 System administrator 配置重新登录后得到 403。

### 12.4 未完成项与阻塞证据

- `frontend/identity-admin/src/data/action-definition-api.ts` 调用 `GET /domain-system-snapshot`、`GET /domain-reference-graph` 和 `/tenant-admin/change-plans/*` 的 validate/save/review/approve/apply。
- 当前 Identity 仓库的 transport route registrar 没有上述任一 endpoint；全仓 Go 搜索也没有 standalone change-plan draft/review/approve/apply application service 或 repository。角色页因此拿不到 `systemSnapshotQuery.data`，`roles.tsx` 在 mutation 前以 `system-draft-not-ready` fail closed。
- `domainry-runtime` 源仓只提供 system snapshot/reference graph 的领域投影与查询入口，也没有 change-plan draft/review/approve/apply transport、application service 或 persistence。
- 完整 `/tenant-admin/change-plans/*` 实现在应用宿主模板 `verdent-template/internal/runtime/...`，并依赖宿主的 system snapshot、reference graph、metadata mutation repository、maker-checker、幂等 apply 和专用 draft/operation persistence；它不是 Identity 内可直接复用的 deployment-neutral 端口。
- 真实页面已经能查看和勾选新的 capability/operation，但点击保存不会形成草稿或发布结果，所以 0.2 的“RoleSchema 保存/发布”和“发布后重启保持”不能勾选。
- Identity 自身已经拥有 RoleSchema metadata definition、version、CAS publication、role directory 同事务投影和 audit 原语，但没有持久化草稿、maker-checker 状态机或宿主 system snapshot/reference graph。因此增加 Identity-native 单步版本发布 API 是一种新的 standalone 产品决策，不等价于现有宿主 change-plan。
- 本次没有用 direct PUT 绕过独立复核、没有造内存草稿、没有复制宿主 change-plan 表/服务；这些做法都会改变既定治理语义或形成第二发布权威。进入下一步前需要确认二选一：S0 standalone 明确定义为 Identity-native RoleSchema 版本发布（复用现有 definition/version/CAS/audit，不承诺宿主 maker-checker），或由应用宿主继续唯一拥有完整 change-plan，S0 的发布验收改在真实宿主 Runtime 中完成。当前代码没有语义等价、可直接复用的第三种实现。

第 3-9 节仍保持未勾选。S0 共 6 个最小验收项，目前 4 个完整通过，2 个由同一个 change-plan/publish 后端契约缺口阻塞；不得把这些 S0 基础提前记作完整 Batch A-F 完成。
