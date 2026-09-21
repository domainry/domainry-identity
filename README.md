# Domainry Identity

Agent-facing question index and source-owned guides: [`capability/agent/index.json`](capability/agent/index.json).

Domainry Identity 是 Domainry 的基础登录与权限模块，负责用户与组织身份、密码及外部身份源登录、会话与 Token、角色与权限、数据访问策略、权限目录和审计能力。

## 代码结构

- `cmd/identity-server/`：独立 Identity 服务的进程入口。
- `module/module.go`：供单体 Runtime 进程内集成的薄公开 facade。
- `internal/assembly/module/`：进程内模块装配实现。
- `internal/assembly/saas/`：独立服务装配和生命周期。
- `internal/adapter/identitysdk/`：`domainry-identity-sdk` 的本地 `Binding` 实现。
- `internal/transport/http/remotesdk/`：远程 SDK 调用所使用的 HTTP 协议。
- `internal/transport/http/module/`：由 Runtime Host 挂载的模块 HTTP adapter。
- `internal/transport/http/saas/`：独立服务 HTTP transport facade；共享路由实现位于 `internal/transport/http/server/`。
- 独立服务的治理审计接口由内嵌 Audit Binding 发布的 `modulehttp` Adapter 提供，Identity Server 只负责认证上下文和挂载，不复制 Audit 查询/导出编排。
- `internal/application/`、`internal/domain/`：应用服务与领域模型。
- `internal/infrastructure/persistence/`：SQLite、MySQL、PostgreSQL 持久化实现。
- Identity 管理界面由 `domainry-plane/frontend/domainry-admin` 统一维护，本仓库只提供后端与 SDK 契约。
- `domainry.template.json`：Identity 默认元数据和初始化数据清单。

Go module 位于仓库根目录：

```text
github.com/domainry/domainry-identity
```

## 集成方式

验证码应用的绑定、接口和 PIN 规则见 [TOTP 接入说明](docs/totp-authentication.md)。

Identity 通过 [`github.com/domainry/domainry-identity-sdk`](https://github.com/domainry/domainry-identity-sdk) 向 Runtime 提供统一契约。两种部署方式最终都向 Plane 暴露同一个 `identitysdk.Binding`。

### 单体模式

业务项目同时依赖 Plane、Identity SDK 和本仓库，并在项目组合入口注入：

```go
import identitymodule "github.com/domainry/domainry-identity/module"

factory := identitymodule.NewFactory(identitymodule.OptionsFromEnvironment())
```

生成项目由 Runtime Host 调用 `module.Factory.OpenWithDatabase`，把项目唯一
数据库连接池借给 Identity。Identity 会：

- 使用 Runtime 拥有的连接池，且不会关闭它；
- 通过 Runtime Host 的 migration registrar 提交 Identity source-owned migration；
- 直接使用宿主指定的 schema，不额外改写任何表名；
- 使用 Module 自己的 Clock（测试可通过 `Options.Clock` 覆盖）；
- 使用 `Factory.Open` 显式传入的 workspace、application key 与回调地址，
  并拒绝跨 workspace/audience 复用同一个 Binding；
- 直接返回进程内 SDK Binding，不产生回环 HTTP 调用。

`Factory.Open` 仍保留给非 Runtime 的独立嵌入场景；该入口才使用
`IDENTITY_MODULE_DATABASE_*` 并自行拥有连接池。

### 独立服务模式

构建并启动 Identity 服务：

```bash
go build -o domainry-identity ./cmd/identity-server
./domainry-identity
```

默认监听 `:8081`。服务包含登录与会话接口、JWKS/OIDC discovery、Identity 管理接口、Browser Gateway，以及供 SDK `remote.Factory` 调用的鉴权和权限目录接口。

Runtime 切换到远程模式后只依赖 Identity SDK，通过 `IDENTITY_ENDPOINT` 等配置访问独立 Identity 服务；业务层仍使用相同的 `identitysdk.Binding`。
远程 Factory 在开放 Binding 前会读取 `/identity/discovery`，校验协议、
策略包、授权合约版本、issuer、SaaS 模式与必要能力；refresh token 也会在原子
轮换之前校验所属 application audience。

## 数据库

当前代码支持三种数据库：

| 数据库 | `DATABASE_DRIVER` | 连接配置 |
| --- | --- | --- |
| SQLite | `sqlite`、`sqlite3`，空值也按 SQLite 处理 | `APP_DB_PATH`，默认 `data/runtime.db`；也可使用 `DATABASE_DSN` |
| MySQL | `mysql` | 必须提供 `DATABASE_DSN`，且 DSN 必须选择 `identity` database |
| PostgreSQL | `postgres`、`postgresql`、`pgx` | 必须提供 `DATABASE_DSN`，且 DSN 必须选择 `identity` database；`DATABASE_SCHEMA` 默认 `public` |

MySQL 和 PostgreSQL 使用各自的标识符、占位符及 schema migration SQL。PostgreSQL 另外支持：

- `DATABASE_CONNECTION_MODE=direct|session_pooler|transaction_pooler`；
- 独立的 `DATABASE_MIGRATION_DSN`；
- 连接池预算、TLS 校验、statement/lock timeout；

Identity 不负责在数据库服务器上创建 database。部署前应由运维创建名为 `identity` 的 database，并为查询账号和迁移账号授予相应权限；服务启动时会拒绝指向其他 database 的 MySQL/PostgreSQL DSN。`DATABASE_MIGRATION_DSN` 如有配置，也必须指向同一个 `identity` database。

Identity 角色定义及其版本由 `_identity_role_definitions`、
`_identity_role_definition_versions` 持久化。业务对象等通用定义只通过
Metadata SDK 的 `Projection`/`Definitions` 业务端口同步和读取；Identity
不再获取 Metadata repository，角色定义不经过 Metadata 表。
通用字典解析和本地化 coverage 由 Metadata owner 提供；Identity 只保留
角色、权限和菜单所需的 Identity 自有本地化投影。

单体模式和独立服务模式使用同一套 Identity 数据库配置、migration 和生命周期；Runtime 不再提供连接池或 schema。

## 主要配置

服务配置来自默认值、项目配置文件、运行时配置文件、Secret 文件、环境变量和远程配置源；优先级由 `internal/platform/config` 统一处理。常用环境变量包括：

```text
APP_ENV
PORT
HTTP_BIND_HOST
DATABASE_DRIVER
DATABASE_DSN
APP_DB_PATH
DATABASE_SCHEMA
TEMPLATE_MANIFEST
AUTH_JWT_SECRET
AUTH_DEFAULT_PASSWORD
IDENTITY_DATA_SECRET_KEY
IDENTITY_APPLICATION_SERVICE_CREDENTIALS
IDENTITY_APPLICATION_PERMISSION_OWNERS
IDENTITY_APPLICATION_RATE_LIMIT_PER_MINUTE
IDENTITY_ACTION_USAGE_RUNTIME_URL
IDENTITY_ACTION_USAGE_REQUEST_TIMEOUT
IDENTITY_ACTION_USAGE_APPLICATION_KEY
IDENTITY_ACTION_USAGE_RUNTIME_AUDIENCE
IDENTITY_ACTION_USAGE_CREDENTIAL_ID
CORS_ALLOWED_ORIGINS
```

`IDENTITY_APPLICATION_SERVICE_CREDENTIALS` 为 Runtime 应用服务凭证映射，格式为
`workspace/application#credential-id=token`，省略 `credential-id` 时默认为 `default`。
多个条目以逗号分隔；同一应用可在轮换窗口配置两个不同 ID 的凭证。每个凭证只能访问
绑定的应用作用域，不同作用域不得复用同一凭证。
`IDENTITY_APPLICATION_PERMISSION_OWNERS` 使用
`workspace/application=source_owner|source_owner` 格式，
显式限制该应用凭证可以 reconcile 的 Permission source owner；多个应用条目以逗号分隔。未列入该集合的
owner 即使使用有效应用凭证也返回 `identity.permission_source_owner_forbidden`。
`IDENTITY_APPLICATION_RATE_LIMIT_PER_MINUTE` 为每个已注册应用独立计算的分钟请求上限，
不会让一个 Runtime 应用耗尽其他应用的额度。

独立部署需要在权限管理页展示 Runtime/module 当前 Action 使用关系时，设置
`IDENTITY_ACTION_USAGE_RUNTIME_URL` 为 Runtime 基础 URL。Identity 会把同一次权限目录请求中的
多个 source owner/key 合并为一个批量请求，调用 Runtime Action 模块的
`POST /action/permission-usages/query`；默认超时由
`IDENTITY_ACTION_USAGE_REQUEST_TIMEOUT=3s` 控制。生产环境只接受 HTTPS URL。

该跨服务调用不转发管理员浏览器 token，也不复用 ops token。Identity 使用
`IDENTITY_ACTION_USAGE_APPLICATION_KEY`（默认 `domainry-identity-control-plane`）、
`IDENTITY_ACTION_USAGE_RUNTIME_AUDIENCE`（默认 `domainry-runtime`）和
`IDENTITY_ACTION_USAGE_CREDENTIAL_ID`（默认 `identity-action-usage`）签发只包含
`runtime.action.permission_usages#query` 的短期 service token。对应 source credential 必须作为
真实轮换记录存在于 `IDENTITY_APPLICATION_SERVICE_CREDENTIALS`，例如：

```text
workspace-primary/domainry-identity-control-plane#identity-action-usage=<source-secret>
```

Runtime 用自己已配置的 verifier credential 调用 Identity 的 token verification endpoint。Runtime
不可达、owner 未加载或响应不合法时，`GET /identity/permissions` 仍返回数据库中的
PermissionDefinition，但该 owner 的 `action_usage_status` 明确为 `unavailable`；Action usage 不写入数据库，
也不会使用上一次远程响应兜底。嵌入部署不配置这些环境变量，Runtime 直接把同一份冻结 Action registry
以进程内 provider 绑定给 Identity。

生产环境会额外校验监听地址、CORS、密钥、PostgreSQL TLS 和数据库能力。不要直接把开发环境默认密钥用于生产。

## 本地验证

```bash
go build ./cmd/identity-server
go test ./...
go vet ./...
```
