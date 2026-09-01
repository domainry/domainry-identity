# Module 权限接入 SOP

状态：作为 `identity-authorization-refactor-todo.md` 的模块接入执行规范；不单独改变数据表方案

更新日期：2026-09-01

当前执行说明：本 SOP 先冻结为后续规范，不作为第一阶段开发门槛。第一阶段只运行 standalone Identity，用 Identity 自有角色管理/功能权限管理接口验证 Action 声明、`_identity_permissions`、角色配置 UI 和实际 2xx/403 闭环。Notification 和其它 module 在该模型经用户确认后再按本文接入。

## 1. 目的和边界

本 SOP 固化一个 Runtime/Identity module 接入后，接口 Action 如何声明、对应 Permission 如何自动初始化到 Identity DB、角色如何通过现有配置流程获得权限，以及请求如何执行校验。

它只采用接口定义规范中的以下原则：

- 管理员通过“功能/页面操作 + HTTP Method/URL”理解权限；
- URL 由 Method + router template 组成，不能只写 path；
- URL 绑定到 stable `ActionKey`，URL 改动不能改变权限身份；
- Action 声明所属能力、操作、页面 binding、授权策略和 Permission；
- Runtime、Identity 内置接口和 module surface 使用同一种 Action 声明语义；
- module 启动时从代码 Action 定义提取 owned PermissionDefinitions，并同步到 `_identity_permissions`。

本 SOP 不改变已经确定的存储模型：

- Action、URL、页面 binding、授权策略和治理声明留在代码/元数据及运行时 `ActionRegistry`；
- Identity 不新增 `_identity_actions`；
- Identity 只将角色可配置的 current PermissionDefinitions 保存到 `_identity_permissions`；
- 不新增 `_identity_permission_usages`、`_identity_permission_resources`、permission bundle/member、role-permission 或 Action/Permission revision 表；
- 角色选择仍写入版本化 `RoleSchema.Permissions`；数据和字段权限仍写入现有 RoleSchema 策略；
- 不建设 Authorization Catalog V2，旧 catalog 在兼容迁移完成后删除。

## 2. 当前代码为什么需要 SOP

当前 module surface 已有可复用的 host gate：

- `domainry-foundation/modulehttp/surface.go` 的 `Route` 已声明 `Pattern`、exposure、authentication、`Permission`/`AnyPermissions`、`PrincipalOnly` 和 governance；
- Runtime `runtime/transport/http/module_http_routes.go` 会先 `ValidateSurface`，再在 `authorizeModuleHTTPRequest` 中校验认证与 `Permission`/`AnyPermissions`，之后校验 governance，最后才进入 module handler；
- Runtime OpenAPI 会从同一 `modulehttp.Route` 投影 owner、surface、exposure、authentication 和权限信息。

但现有 `modulehttp.Route` 还不能完整回答以下问题：

- 这条接口的 stable `ActionKey` 是什么；
- 它在角色配置页属于哪个功能和哪个用户可理解操作；
- 它对应哪个管理页面；
- route 引用的 Permission 由谁定义、如何自动初始化到 Identity；
- self、dynamic owner policy、ops 等策略是否被错误压成 `PrincipalOnly`。

Identity 自己也存在同样问题：

- `internal/transport/http/identity/identity_routes.go` 在路由注册旁手写 Permission；
- `internal/assembly/module/factory.go` 把管理路由贡献为统一的 `Authenticated + PrincipalOnly`，丢失真实 route Permission；
- `internal/domain/identity/contract/identity_admin_routes.go` 又独立维护 `/admin/... -> permission` 页面映射。

因此 SOP 的目标是形成一份 source-owned manifest，并从它投影 route mounting、host gate、OpenAPI、配置页说明和 owned PermissionDefinitions，而不是再增加一张数据库表。

## 3. 接口 Action 声明规范

Batch B 应在 deployment-neutral shared contract 中补齐下列语义。最终 Go 类型名可以在实现时结合 `modulehttp.Route` 评审，但字段职责不可缩水。

| 字段 | 必填规则 | 示例 |
| --- | --- | --- |
| `Owner` | canonical source owner；一个 Permission 只能有一个 owner | `notification` |
| `ActionKey` | 全局稳定的可执行操作 key；不能用原始 URL 代替 | `notification.templates.list` |
| `CapabilityKey` | 角色配置页面功能分组 | `notification.template_management` |
| `CapabilityLabel` | 用户可读功能名 | `通知模板管理` |
| `OperationKey` | list/read/create/update/delete/approve 等稳定操作 | `read` |
| `OperationLabel` | 用户看到的操作名 | `查看` |
| `Pattern` | HTTP Method + router template；非 HTTP Action 使用独立 binding kind | `GET /notifications/templates` |
| `PageRoutes` | 可选页面/菜单 binding；只用于展示和可见性，不替代后端校验 | `/admin/notifications/templates` |
| `Exposures` | public/tenant-admin/ops 挂载位置 | `tenant_admin` |
| `AuthorizationStrategy` | anonymous/authenticated/self/service/static all/static any/dynamic/ops 之一 | `static_any` |
| `RequiredPermissions` | Action 引用的 all/any Permission keys；不能同时使用互斥模式 | `workspace.admin` 或 `notification.template.read` |
| `OwnedPermissionDefinitions` | 仅 canonical owner 声明；包含 key、resource/action label、category、description | `notification.template.read` |
| `Governance` | effect、high-risk、idempotency、audit；写接口不得省略 | `write/natural_key/...` |
| `Lifecycle` | active、compatibility tombstone 或 retired；兼容接口必须明确 | `active` |

规范化示意，不代表要求新增同名 Builder 或 JSON 文件：

```go
ActionRoute{
    Owner:           "notification",
    ActionKey:       "notification.templates.list",
    CapabilityKey:   "notification.template_management",
    CapabilityLabel: "通知模板管理",
    OperationKey:    "read",
    OperationLabel:  "查看",
    PageRoutes:      []string{"/admin/notifications/templates"},
    Route: modulehttp.Route{
        Pattern:        "GET /notifications/templates",
        Exposures:      []modulehttp.Exposure{modulehttp.ExposureTenantAdmin},
        Authentication: modulehttp.AuthenticationAuthenticated,
        AnyPermissions: []string{"workspace.admin", "notification.template.read"},
        Governance:     readGovernance,
    },
    OwnedPermissionDefinitions: []PermissionDefinition{
        {
            Key:         "notification.template.read",
            ResourceKey: "notification.template",
            ActionKey:   "read",
            Label:       "查看通知模板",
            Category:    "通知管理",
        },
    },
}
```

共享 contract 不应持有 handler/function pointer。module 可以在自己的 transport 包中使用本地 manifest entry 将 `ActionRoute` 与 handler 关联，然后同时生成 `Surface.Routes()` 和 mux registration；这样 `Routes()` 与 `HandleFunc()` 不再各维护一份 Pattern。

## 4. 声明规则

### 4.1 Action 与 Permission

- 一条实际可执行 endpoint 对应一个 stable Action；list/get 即使共享 read Permission，也保留各自 ActionKey。
- 默认一个可授权语义操作拥有同 namespace Permission；多个 endpoint 只有在产品语义相同且代码明确声明时才共享 Permission。
- `workspace.admin` 是 Identity 拥有的保留 wildcard。module 可以引用它作为 any-of 分支，但不能把它作为自己 owned Permission 重复同步。
- module 只同步自己 canonical-owned 的 PermissionDefinition；引用其它 owner Permission 不取得定义权。
- 不同 owner 定义同一个 permission key，或者 Action 引用未知/retired/disabled Permission，装配或请求必须 fail closed。
- Permission key 不以 HTTP method/path 命名。URL 变化只改 binding，不改 ActionKey 或 Permission key。

### 4.2 管理页面展示

角色配置页按 `CapabilityKey + OperationKey` 聚合 ActionRegistry 的接口信息，并与 DB 中 active+enabled PermissionDefinition 合并：

```text
通知模板管理
  查看
    GET /notifications/templates
    GET /notifications/templates/{templateKey}
  编辑草稿
    PUT /notifications/templates/{templateKey}/draft
  提交发布
    POST /notifications/templates/{templateKey}/publication-requests
```

管理员勾选的是“查看/编辑草稿/提交发布”。保存时写 stable permission keys 到 `RoleSchema.Permissions`；页面 route 只是说明和菜单投影，不是授权证据。

若 ActionRegistry owner 暂时不可达，Identity 仍可显示 DB PermissionDefinition 和角色引用状态，但 URL usage 必须明确显示 unavailable，不能用数据库历史值冒充当前代码事实。

### 4.3 动态对象接口

`GET /objects/{objectKey}/records` 仍是实际 router template，但不能成为角色可选择的全对象 wildcard。metadata activation 必须为每个 active ObjectSchema 生成具体运行时 Action/Permission 语义：

```text
customer.records.list -> customer.read
order.records.list    -> order.read
```

请求进入后由 dynamic resolver 使用 path 中的 `objectKey` 和 method/operation 解析具体 Action；配置投影显示 `/objects/customer/records` 等具体 URL。Identity 只保存 `customer.read`、`order.read` 等 PermissionDefinitions，不保存对象或 URL 副本。

### 4.4 非角色策略

- anonymous protocol、health/probe 必须显式声明 anonymous；不得因没有 Permission 自动公开。
- principal-only 只用于确实“任意已登录主体都能调用”的能力，不能代替管理权限。
- 本人或权限分支必须声明 self-or-permission；不能藏在 handler 里。
- service、ops 使用独立 credential/audience/scope 策略；不能靠 `workspace.admin` 越权。
- module application service 保留 resource/action、数据范围和领域 guardrail 的最终校验；host URL gate 不是唯一授权层。

## 5. 固定接入流程

### Step 1：盘点 module 权限事实

接入者先列出并对齐：

- 所有 `modulehttp.Surface.Routes()`；
- mux/handler 实际注册的 Method + Pattern；
- OpenAPI operations；
- host `Permission`/`AnyPermissions`；
- module application service 内部 resource/action 授权；
- 旧 AuthorizationCatalog/Runtime hardcode；
- 管理页面和菜单 route guard；
- 当前 RoleSchema、permission set 和系统角色实际引用的旧 keys。

盘点必须输出差异清单，不能直接选择其中任意一份当真相。

### Step 2：确定 canonical vocabulary 和兼容迁移

- 为每个 endpoint 确定 ActionKey、capability、operation 和授权策略；
- 为每个角色可配能力确定唯一 Permission key 和 canonical owner；
- 明确多个 Action 是否共享一个 Permission；
- 建立旧 Permission key 到新 key 的等价映射；
- 对已发布 RoleSchema/permission sets 生成受审计的新版本迁移，不能原地改写历史版本；
- 旧 alias 只在迁移窗口生效，不展示给新角色配置，引用清零后 retired 并删除 alias。

### Step 3：建立一份 source-owned manifest

- module transport 只维护一份 Action route manifest；
- `Surface.Routes()`、mux registration、OpenAPI projection、host gate 和配置 projection 从同一 manifest 生成或进行严格一一校验；
- owned PermissionDefinitions 从同一 manifest 汇总、去重并校验字段一致；
- 不再维护 module Catalog Action、Runtime module-specific catalog hardcode 或独立页面 permission map。

### Step 4：装配前验证

host 在监听器 ready 前验证：

- owner、ActionKey、Pattern、capability、operation、authorization strategy 完整；
- Method + Pattern 可被 router 接受且无重复/冲突；
- 每条实际 mux route 都有声明，每条声明也有 handler；
- non-public route 不存在隐式放行；
- Permission owner 唯一，required references 全部可解析；
- governance 对 write/high-risk route 完整；
- OpenAPI route 和 Action manifest 一一对应；
- 页面 route 只作投影，没有被当成后端授权。

任何冲突都拒绝 ready，不能只记录 warning 后挂载。

### Step 5：初始化 Permission 到 Identity DB

装配通过后，按 source owner 汇总完整 owned PermissionDefinition snapshot：

```text
validate candidate ActionRegistry
  -> derive owner-owned PermissionDefinitions
  -> reconcile _identity_permissions
  -> receive success receipt
  -> freeze/activate ActionRegistry
  -> mount surface and report ready
```

reconcile 规则：

- 相同 snapshot 重复启动幂等；
- 新 Permission 插入 active+enabled；
- code-owned 文案/分类/hash 可更新，但保留管理员 `enabled`；
- 同 owner 本次缺失的 Permission 标记 retired，不物理删除；
- 新 Permission 只成为角色可选项，不自动授予普通角色；
- owner 冲突、stale snapshot 或数据库失败时，不激活候选 surface；
- embedded 模式使用宿主 DB、transaction、dialect、migration lock 和唯一 `_schema_migrations`；
- standalone/remote 模式使用 service credential 调用同一 reconcile 合约。

### Step 6：角色正常配置

- 配置 API 从 ActionRegistry 获取功能/操作/Method+URL/page bindings，从 Identity DB 获取 Permission active/enabled/retired 状态；
- UI 只允许选择 active+enabled Permission；
- 保存继续走 RoleSchema version/change/validation/publish 流程；
- PermissionDefinition 没有 draft/publish/version 页面；
- 不新增 role-permission assignment 表；
- 数据范围和字段权限继续保存到现有 RoleSchema data/field policy，由 Runtime 根据当前 ObjectSchema 执行。

### Step 7：请求校验

```text
router 匹配 Method + Pattern
  -> 解析 stable ActionKey
  -> 执行 Action authorization strategy
  -> 校验 required Permission 是否 active+enabled
  -> 校验 AccessBundle grant / wildcard / deny guardrail
  -> module application service 校验内部 resource/action 和数据范围
  -> 执行 handler 并审计
```

请求热路径不查 `_identity_permissions` 一次一条，也不解析 catalog JSON。Identity Permission state 和 ActionRegistry 在 revision 变化时编译成不可变快照；未知 Action/Permission 和 stale incompatible snapshot fail closed。

### Step 8：升级、删除与卸载

- URL 改动保留 ActionKey/Permission key；同步更新 handler、OpenAPI 和页面投影；
- 新 Action 产生新 Permission 可选项，但不自动给已有角色扩权；
- 删除 Action 后，只有当 owner 不再有任何 Action 使用对应 owned Permission，Permission 才在完整 snapshot reconcile 中 retired；
- Permission 重命名必须先完成角色/permission-set 等价迁移；
- module 卸载保留 retired Permission 和角色引用治理报告，不能物理删除后让历史授权不可解释。

## 6. Notification 首个接入样例

### 6.1 当前差异证据

Notification 当前正好说明为什么需要 SOP：

1. `internal/transport/http/module/capability_contract.go` 的 `ProductRoutes()` 是现有 source-owned HTTP manifest，但 host 权限使用 `notification.template.read/manage/approve/publish` 等 dotted keys。
2. `internal/adapter/identitysdk/identity.go` 的旧 `Catalog()` 另行声明 `notification_template.read/draft/preview/disable`、`notification_publication.request/approve/...` 等 resource/action。
3. `internal/assembly/module/services.go` 的最终领域校验使用 `notification_template + draft`、`notification_publication + approve` 等 resource/action。
4. Runtime `runtime/bootstrap/runtime/identity_catalog.go` 再手写一份 Notification resource/action 列表。
5. `NewSurface()` 虽然复用 `ProductRoutes()` 作为 disclosure，但 mux `HandleFunc()` 仍单独手写 Pattern，存在继续漂移的可能。

这五处不能直接选一份覆盖其它代码，必须先做语义等价审计。

### 6.2 目标 vocabulary 示例

以下是待实现时逐项测试确认的目标形态；canonical Permission 建议采用现有平台一致的 dotted namespace，内部 resource/action 继续作为 module 执行语言：

| Method + URL | ActionKey | 角色可配 Permission | module 内部执行 |
| --- | --- | --- | --- |
| `GET /notifications/templates` | `notification.templates.list` | `notification.template.read` | `notification_template/read` |
| `GET /notifications/templates/{templateKey}` | `notification.templates.get` | `notification.template.read` | `notification_template/read` |
| `PUT /notifications/templates/{templateKey}/draft` | `notification.templates.save_draft` | `notification.template.draft` | `notification_template/draft` |
| `POST /notifications/templates/{templateKey}/preview` | `notification.templates.preview` | `notification.template.preview` | `notification_template/preview` |
| `POST /notifications/templates/{templateKey}/disable` | `notification.templates.disable` | `notification.template.disable` | `notification_template/disable` |
| `GET /notifications/publications` | `notification.publications.list` | `notification.publication.read` | `notification_publication/read` |
| `POST /notifications/templates/{templateKey}/publication-requests` | `notification.publications.request` | `notification.publication.request` | `notification_publication/request` |
| `POST /notifications/publications/{publicationID}/approve` | `notification.publications.approve` | `notification.publication.approve` | `notification_publication/approve` |
| `POST /notifications/publications/{publicationID}/reject` | `notification.publications.reject` | `notification.publication.reject` | `notification_publication/reject` |
| `POST /notifications/publications/{publicationID}/cancel` | `notification.publications.cancel` | `notification.publication.cancel` | `notification_publication/cancel` |

`workspace.admin` 继续作为 any-of 的 Identity-owned 保留能力。旧 `notification.template.manage/approve/publish/test` 需要根据它们今天实际覆盖的 endpoints 展开为等价 granular keys，并迁移既有角色；不能用一次字符串替换猜测。

Business/Portal Inbox routes需要单独审计。若它们确实只允许当前主体访问本人 Inbox，声明 authenticated principal/self 策略，不生成普通角色 Permission；委托、团队邮箱或治理接口仍按实际管理语义声明 Permission。

### 6.3 Notification 改造顺序

1. 为 `ProductRoutes()` 每条 route 补齐 stable Action/capability/operation/page metadata，并建立 route-to-handler 一一校验。
2. 审计 dotted host permissions 与内部 resource/action，确定 canonical Permission keys 和旧 key 迁移表。
3. 从同一 manifest 生成 `Surface.Routes()`、OpenAPI extension、host gate 和 owned PermissionDefinitions。
4. Runtime 装配时从 Notification manifest 汇总 PermissionDefinitions 并 reconcile 到 `_identity_permissions`；receipt 成功后才激活 surface。
5. 删除 Runtime `identity_catalog.go` 的 Notification 专用硬编码。
6. standalone Notification 切换到 Permission reconcile + application registration 后，删除其 `Catalog()` 发布逻辑。
7. 保留 module application service 的 `notification_template/...`、`notification_publication/...` 领域校验，并增加 host Permission 与内部 resource/action 映射一致性测试。
8. 完成 RoleSchema/permission-set 等价迁移后，将旧 broad permissions retired。

## 7. 后续 module 推广的最小验收清单

- [ ] 每条实际接口都有唯一 ActionKey、Method+Pattern、capability/operation 和显式授权策略。
- [ ] Surface routes、handler routes、OpenAPI operations 和 Action manifest 集合完全一致。
- [ ] 每个 required Permission 有且只有一个 canonical owner；共享 Permission 有显式 reuse。
- [ ] owned PermissionDefinitions 能在空 workspace 启动后自动出现在 `_identity_permissions`。
- [ ] 重复启动幂等，管理员 disabled 状态不会被代码同步覆盖。
- [ ] 新增 Permission 不自动授予普通角色；角色配置仍走 RoleSchema 正常版本流程。
- [ ] ActionRegistry 配置投影能显示功能/操作/Method+URL/page；Identity 不存 Action/URL 副本。
- [ ] host 缺权限返回 403；未知/disabled/retired Permission fail closed。
- [ ] module application service 的内部 resource/action 和数据范围校验仍存在并有越权测试。
- [ ] 旧 Catalog/Runtime hardcode/page permission map 在迁移完成后删除，全仓不存在 module-specific 第二份权限词汇。

跨部署全策略矩阵、三方言、卸载治理和全仓回归仍保留在主 TODO 的最终验收阶段，不在 standalone UI/API 原型阶段提前阻塞开发。
