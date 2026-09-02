# Module 权限接入 SOP

状态：`identity-authorization-refactor-todo.md` 的强制模块接入规范
更新日期：2026-09-02

## 1. 目标与不变量

Module 接入必须把每个可执行入口声明成 source-owned `ActionDefinition`。宿主从 Action 提取角色可配置的同 key `PermissionDefinition`，经 Identity reconcile 成功后才允许 surface ready。

必须同时满足以下不变量：

- 一个可执行入口对应一个稳定 Action key；HTTP URL 只是 binding，不是权限身份。
- 角色授权 Action 只拥有并校验一个与 Action key、owner 完全相同的 Permission。
- 不存在 Permission reuse、all/any 权限列表、alias、wildcard grant 或动态 permission resolver。
- 不存在 workspace-wide 管理员 Permission；管理员角色也必须显式列出每个 module Action 的同 key Permission。
- 非角色策略必须显式声明；没有 Permission 不等于公开。
- module 只维护一份 Action manifest；route、host gate、OpenAPI、Identity reconcile 和配置投影都从它产生。
- Action、URL、页面和治理声明不落 Identity DB；Identity 只持久化 current PermissionDefinition 状态。
- `RoleSchema.Permissions` 是功能 Action grant 的唯一角色权威；不新增 role-permission 表。
- module application service 保留最终领域校验，宿主 transport gate 不是唯一授权边界。
- embedded module 借用宿主 DB、transaction、dialect、migration lock 和唯一 `_schema_migrations` ledger。

## 2. Canonical Action 合约

规范类型位于 `github.com/domainry/domainry-foundation/action`。module HTTP route 直接携带完整 `ActionDefinition`，不得再声明第二份 permission 字符串。

| 字段 | 规则 |
| --- | --- |
| `Key` | 全局稳定的可执行操作 key，例如 `notification.templates.list` |
| `Owner` | canonical source owner，例如 `module:notification` |
| `SourceKind` | module surface 使用 `module_surface` |
| `CapabilityKey/Label` | 配置页的功能分组及用户可读名称 |
| `OperationKey/Label` | list/get/create/update/approve 等精确语义 |
| `Exposures` | `public`、`tenant_admin`、`ops` 中显式选择 |
| `Authorization` | 恰好一种受支持策略 |
| `HTTP` | Method + router template；URL 变化不能迫使 Action key 改名 |
| `Pages` | 可选页面/菜单投影，不替代后端授权 |
| `NonHTTP` | RPC/job/agent 等调用 binding；纯非 HTTP module 入口也必须进入宿主 ActionRegistry |
| `Permission` | 仅角色授权或 self 管理分支需要；key/owner 必须与 Action 相同 |
| `Effect/Risk/Assurance/Approval/Idempotency/Audit` | Action 自身的执行治理事实 |
| `LifecycleStatus` | `active`、`deprecated` 或 `retired`；未上线代码不保留兼容 tombstone |

受支持策略与 Permission 规则：

| Strategy | 使用场景 | 同 key Permission |
| --- | --- | --- |
| `exact_role_permission` | module 管理和业务能力 | 必须有；只校验该 key |
| `anonymous_protocol` | 明确公开的协议入口 | 不得有 |
| `authenticated_principal` | 任意已登录主体的本人范围能力 | 不得有 |
| `self_or_permission` | 本人可操作，管理他人需授权 | 必须有；管理分支只校验该 key |
| `delegated_credential` | agent/tool 等由 source handler 校验的 workspace 级委托凭证 | 不得有；handler 必须校验凭证 scope、expiry 和精确 tool/action 绑定 |
| `service_identity` | 明确 audience 的服务身份入口 | 不得有普通角色 Permission |
| `operations_identity` | 运维身份策略 | 不得有普通角色 Permission |

示例：

```go
action.ActionDefinition{
    Key:           "notification.templates.list",
    Owner:         "module:notification",
    SourceKind:    "module_surface",
    CapabilityKey: "notification.management",
    OperationKey:  "list",
    Exposures:      []action.Exposure{action.ExposureTenantAdmin},
    Authorization:  action.Authorization{Strategy: action.AuthorizationExactRolePermission},
    HTTP:           &action.HTTPBinding{Method: "GET", RouteTemplate: "/notifications/templates"},
    Permission: &action.PermissionDefinition{
        Key:         "notification.templates.list",
        Owner:       "module:notification",
        ResourceKey: "notification.templates",
        OperationKey: "list",
        Label:       "List notification templates",
        Category:    "Notification management",
    },
}
```

共享合约不得保存 handler/function pointer。module transport 使用本地 `map[actionKey]handler` 绑定实现；Method/URL 必须从 Action 读取。装配时缺 handler、额外 handler、重复 Action、重复 HTTP binding 或 OpenAPI 集合漂移都必须报错。

## 3. 唯一 source manifest

每个 module 提供一个 source-owned Action 构造入口，例如：

```go
func AuthorizationActions() ([]action.ActionDefinition, error)
```

以下产物只能是它的投影：

1. `modulehttp.Surface.Routes()`：对具有 HTTP binding 的 Action 使用 `modulehttp.RouteFromAction`。
2. mux registration：通过 `route.Action.Key` 找 handler，通过 `route.Pattern()` 注册 Method/URL。
3. host authentication/authorization/governance gate：直接执行 `route.Action.Authorization` 和同 key Permission。
4. OpenAPI：operation extension 读取同一个 Action 的 owner、strategy、Permission、effect 和 idempotency。
5. Identity reconcile：只提取 `Action.Permission != nil` 的定义，不能另写 module Catalog。
6. 配置树和页面说明：从冻结后的 live ActionRegistry 投影；Identity 不保存 URL 副本。

Runtime、Identity 或其它宿主不得维护 module-specific Action/Permission hardcode。

`modulehttp.Surface` 只承载具有 HTTP binding 的 module Action。纯 HTTP module 可由宿主直接从 `Route.Action` 提取完整清单；同时存在 RPC/job/agent Action 的 module 必须由 Binding 实现 `action.Provider`，通过 `AuthorizationActions()` 提交包含 HTTP 与非 HTTP 入口的完整 canonical manifest。宿主必须用 `modulehttp.ValidateAuthorizationProjection` 证明所有 active HTTP Action 与实际 Surface 一一对应，再把同一批 Action 纳入统一 Registry；不得用独立权限 Catalog 绕过该入口。

## 4. 接入流程

### Step 1：盘点事实

逐项核对：

- 实际 handler/mux、RPC、job、agent 入口；
- `Surface.Routes()` 和 OpenAPI；
- module application service 的最终授权；
- 旧 Catalog、Runtime hardcode、页面 permission map 和角色 seed；
- embedded 与 SaaS 两种装配路径。

盘点后为每个入口确定唯一 Action key 和 strategy。当前代码未上线，旧 broad key、旧 URL tombstone 和旧 Catalog 直接删除，不建立映射、双 grant 或历史迁移。

### Step 2：构建并验证候选 Registry

宿主在 ready 前批量合并 Object、authored、built-in 和所有 module Action contributions，并验证：

- Action 字段和授权策略完整；
- role/self Action 的 Permission 与 Action key/owner 完全相同；
- Permission owner 唯一；
- Action key、HTTP 和 non-HTTP binding 无冲突；
- active Action 有实际执行入口；
- route、handler 和 OpenAPI 集合一一对应；
- public/protocol 入口显式声明，不允许因漏 wrapper 放行。

任何错误都拒绝候选 Registry，不得部分发布。

### Step 3：批量 reconcile PermissionDefinitions

按 owner 从完整候选 Registry 提取完整 PermissionDefinition snapshot：

```text
build and validate candidate ActionRegistry
  -> group same-key PermissionDefinitions by canonical owner
  -> register target application
  -> reconcile one complete snapshot per owner
  -> validate receipt workspace/owner/previous hash/new hash/count
  -> atomically publish frozen Registry
  -> mount surfaces and report ready
```

规则：

- reconcile 是 owner 级批量操作，Identity persistence 不得逐条 DML。
- 相同 snapshot 重试幂等；管理员维护的 `enabled` 不被代码覆盖。
- 新 Permission 默认 active+enabled，但不自动加入任何普通角色。
- 同 owner 从完整 snapshot 消失的 Permission 标为 retired，不物理删除。
- owner 冲突、stale snapshot、receipt 不匹配或数据库失败都拒绝 ready。
- remote caller 必须使用 SDK 构造 snapshot hash，并验证成功 receipt。
- changed snapshot 必须携带上一次确认的 snapshot hash；空 previous hash 只适用于 fresh owner 或同 snapshot 幂等重试。跨进程升级必须有可靠的已确认 hash 来源，不能猜测或跳过并发保护。

### Step 4：执行请求

```text
resolve registered Action
  -> validate declared identity strategy
  -> exact-role/self-management branch checks current Permission active+enabled
  -> check RoleSchema.Permissions exact Action key
  -> apply deny guardrail
  -> apply module-owned resource/data/domain rules
  -> execute and audit
```

请求热路径不逐条查询 `_identity_permissions`，也不解析 Catalog JSON。宿主从已编译的 Action/authorization snapshot 执行公共门禁；module application service 对 durable job、恢复执行和直接 SDK 调用再次执行当前 Action 授权。

动态 Object router 不是 dynamic permission 策略。它必须先把 `{objectKey}+operation` 解析成已经注册的具体 Action（例如 `customer.read`），再执行普通同 key Permission 校验。

## 5. 升级、删除与卸载

- 修改 Method/URL/page 只更新 Action binding，保留 Action/Permission key。
- 新 Action 产生新的同 key Permission，但不自动给已有角色扩权。
- 删除 Action 后，由 owner 的完整下一版 snapshot 将其 Permission retired。
- module 卸载向 Identity reconcile 空 snapshot，保留 retired 定义和角色引用治理事实。
- 当前代码未上线，旧 key 直接删除；不引入 rename alias、双重 grant、兼容 endpoint 或角色历史迁移。
- changed snapshot reconcile 必须基于最后确认的 previous hash；启动重试、响应丢失和进程重启都要有测试。

## 6. Notification 首个接入样例

Notification 的唯一 manifest 是 `internal/application/authorization_actions.go`：

- 21 个管理 Action 使用 `exact_role_permission`，ActionKey 与 PermissionKey 完全相同；
- 40 个 Business/Portal Inbox Action 使用 `authenticated_principal`，由领域服务限制到当前主体，不生成普通角色 Permission；
- `ProductRoutes()`、Surface、OpenAPI 和 SaaS Permission reconcile 都从该 manifest 投影；
- handler map 只绑定 Action key 到函数，不重复 Method/URL；
- resumed publication 只接受 `notification.publications.approve`，不接受任何聚合管理员权限或旧 `notification_publication.approve`；
- 旧 direct-publish tombstone、旧 Catalog 和 Runtime Notification 权限硬编码直接删除。

代表性精确 vocabulary：

| Method + URL | ActionKey = PermissionKey |
| --- | --- |
| `GET /notifications/templates` | `notification.templates.list` |
| `GET /notifications/templates/{templateKey}` | `notification.templates.get` |
| `PUT /notifications/templates/{templateKey}/draft` | `notification.templates.draft.save` |
| `POST /notifications/templates/{templateKey}/preview` | `notification.templates.preview` |
| `POST /notifications/templates/{templateKey}/publication-requests` | `notification.publications.request` |
| `GET /notifications/publications` | `notification.publications.list` |
| `POST /notifications/publications/{publicationID}/approve` | `notification.publications.approve` |
| `POST /notifications/publications/{publicationID}/reject` | `notification.publications.reject` |
| `POST /notifications/publications/{publicationID}/cancel` | `notification.publications.cancel` |

module application service 将同一个 Action key 拆成 SDK 的 object/action 请求字段只是 wire projection，不形成另一套权限词汇。

## 7. Module ready 验收清单

- [ ] 每个 HTTP/RPC/job/agent 入口都有唯一 Action 和显式 strategy。
- [ ] Action manifest、实际 handler、Surface routes 和 OpenAPI 集合完全一致。
- [ ] 每个角色授权 Action 只拥有同 key、同 owner Permission；不存在 reuse/all/any/wildcard。
- [ ] host generic registry 无 module-specific hardcode。
- [ ] owner 完整 snapshot 能在 fresh workspace 批量初始化 `_identity_permissions`。
- [ ] reconcile request hash 和 receipt 均验证；错误 receipt 在 mount 前 fail closed。
- [ ] 重复启动幂等，changed snapshot 使用最后确认 hash，响应丢失重试不会重复或乱序覆盖。
- [ ] 新 Permission 不自动授权；unknown/disabled/retired Permission fail closed。
- [ ] host gate 和 module application service 最终授权都有 2xx/403 越权测试。
- [ ] URL 改动、Action 删除、module 卸载和进程重启行为有测试。
- [ ] embedded/SaaS 对相同 Action、角色和资源事实得到相同授权结论。
- [ ] 纯非 HTTP module Action 已进入同一 ActionRegistry；不存在旁路 Catalog。
