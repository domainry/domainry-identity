# Domainry Identity

Domainry Identity 是 Domainry 的基础登录与权限模块，负责用户与组织身份、密码及外部身份源登录、会话与 Token、角色与权限、数据访问策略、权限目录和审计能力。

## 代码结构

- `main.go`：独立 Identity 服务的进程入口。
- `module/`：供单体 Runtime 进程内集成的公开 Go 包。
- `internal/assembly/`：单体与独立服务共享的应用装配和生命周期。
- `internal/adapter/identitysdk/`：`domainry-identity-sdk` 的本地 `Binding` 实现。
- `internal/transport/http/remotesdk/`：远程 SDK 调用所使用的 HTTP 协议。
- `internal/transport/http/server/`：独立服务 HTTP 路由、浏览器网关和管理接口装配。
- `internal/application/`、`internal/domain/`：应用服务与领域模型。
- `internal/infrastructure/persistence/`：SQLite、MySQL、PostgreSQL 持久化实现。
- `frontend/identity-admin/`：Identity 管理前端。
- `domainry.template.json`：Identity 默认元数据和初始化数据清单。

Go module 位于仓库根目录：

```text
github.com/domainry/domainry-identity
```

## 集成方式

Identity 通过 [`github.com/domainry/domainry-identity-sdk`](https://github.com/domainry/domainry-identity-sdk) 向 Runtime 提供统一契约。两种部署方式最终都向 Plane 暴露同一个 `identitysdk.Binding`。

### 单体模式

业务项目同时依赖 Plane、Identity SDK 和本仓库，并在项目组合入口注入：

```go
import identitymodule "github.com/domainry/domainry-identity/module"

factory := identitymodule.NewFactory(identitymodule.OptionsFromEnvironment())
```

`module.Factory.Open` 只接收 SDK 的应用上下文。Identity 会：

- 自己打开并关闭 Identity 数据库连接池；
- 自己执行和校验 Identity schema migration；
- 使用 Module 自己的 Clock（测试可通过 `Options.Clock` 覆盖）；
- 使用 `Factory.Open` 显式传入的 workspace、application key 与回调地址，
  并拒绝跨 workspace/audience 复用同一个 Binding；
- 只读取 `IDENTITY_MODULE_DATABASE_*` 持久化配置，绝不继承 Runtime 的
  `DATABASE_DRIVER`、`DATABASE_DSN` 或 `APP_DB_PATH`；
- 直接返回进程内 SDK Binding，不产生回环 HTTP 调用。

### 独立服务模式

构建并启动 Identity 服务：

```bash
go build -o domainry-identity .
./domainry-identity
```

默认监听 `:8081`。服务包含登录与会话接口、JWKS/OIDC discovery、Identity 管理接口、Browser Gateway，以及供 SDK `remote.Factory` 调用的鉴权和权限目录接口。

Runtime 切换到远程模式后只依赖 Identity SDK，通过 `IDENTITY_ENDPOINT` 等配置访问独立 Identity 服务；业务层仍使用相同的 `identitysdk.Binding`。
远程 Factory 在开放 Binding 前会读取 `/identity/discovery`，校验协议、
策略包、Catalog、issuer、SaaS 模式与必要能力；refresh token 也会在原子
轮换之前校验所属 application audience。

## 数据库

当前代码支持三种数据库：

| 数据库 | `DATABASE_DRIVER` | 连接配置 |
| --- | --- | --- |
| SQLite | `sqlite`、`sqlite3`，空值也按 SQLite 处理 | `APP_DB_PATH`，默认 `data/identity.db`；也可使用 `DATABASE_DSN` |
| MySQL | `mysql` | 必须提供 `DATABASE_DSN`，且 DSN 必须选择 `identity` database |
| PostgreSQL | `postgres`、`postgresql`、`pgx` | 必须提供 `DATABASE_DSN`，且 DSN 必须选择 `identity` database；`DATABASE_SCHEMA` 默认 `public` |

MySQL 和 PostgreSQL 使用各自的标识符、占位符及 schema migration SQL。PostgreSQL 另外支持：

- `DATABASE_CONNECTION_MODE=direct|session_pooler|transaction_pooler`；
- 独立的 `DATABASE_MIGRATION_DSN`；
- 连接池预算、TLS 校验、statement/lock timeout；
- 可选的 workspace RLS。

Identity 不负责在数据库服务器上创建 database。部署前应由运维创建名为 `identity` 的 database，并为查询账号和迁移账号授予相应权限；服务启动时会拒绝指向其他 database 的 MySQL/PostgreSQL DSN。`DATABASE_MIGRATION_DSN` 如有配置，也必须指向同一个 `identity` database。

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
IDENTITY_APPLICATION_RATE_LIMIT_PER_MINUTE
CORS_ALLOWED_ORIGINS
```

`IDENTITY_APPLICATION_SERVICE_CREDENTIALS` 为 Runtime 应用服务凭证映射，格式为
`tenant/workspace/application#credential-id=token`；当 tenant 与 workspace 相同时可写成
`workspace/application#credential-id=token`，省略 `credential-id` 时默认为 `default`。
多个条目以逗号分隔；同一应用可在轮换窗口配置两个不同 ID 的凭证。每个凭证只能访问
绑定的应用作用域，不同作用域不得复用同一凭证。
`IDENTITY_APPLICATION_RATE_LIMIT_PER_MINUTE` 为每个已注册应用独立计算的分钟请求上限，
不会让一个 Runtime 应用耗尽其他应用的额度。

生产环境会额外校验监听地址、CORS、密钥、PostgreSQL TLS 和数据库能力。不要直接把开发环境默认密钥用于生产。

## 本地验证

```bash
go build .
go test ./...
go vet ./...
npm --prefix frontend run build
npm --prefix frontend run test:unit --workspace identity-admin
```
