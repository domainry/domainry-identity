# Identity 扩展能力 TODO

状态：待实施

更新日期：2026-09-02

上位规划：本文件是 Identity 专项明细；跨模块统一扩展入口、各模块切入点和实施顺序见 `module-extension-architecture-todo.md`。

## 1. 目标

Identity 核心模型保持稳定，客户无需修改或 fork `domainry-identity/module`，即可在宿主项目中扩展业务 Profile 字段、业务事实、绑定规则和展示投影。

扩展能力必须同时保持以下边界：

- Identity 继续拥有账号、认证、会话、Token、角色、权限和 Profile Binding 治理事实。
- 客户自定义字段属于客户自己的业务 Profile 对象，不直接向 `_identity_users` 增加列。
- Profile 通过显式、唯一的 Identity relation 关联 `identity_user`。
- Embedded module 使用宿主数据库、事务、SQL 方言、migration lock 和唯一 `_schema_migrations` ledger。
- 客户扩展不能绕过 workspace 隔离、授权、审计、幂等、乐观锁和高风险操作审批。
- module 与 SaaS 部署必须暴露等价的业务语义、错误码和能力发现结果。

## 2. 当前代码基线

当前仓库已经具备以下基础：

- `IdentityProfileExtension` 可以声明业务 Profile 对象、Identity relation、摘要字段、Profile Tab、可见性和所需权限。
- Metadata candidate 支持 `field` 和 `identity_profile_binding` 资源变更。
- `IdentityProfileBindingApplicationService` 已实现 `invite`、`claim`、`bind`、`rebind` 和 `unlink` 业务流程。
- Identity Profile Binding persistence 已具备幂等 receipt、乐观锁、事件记录和 system-managed role 同步。

当前主要缺口：

- Profile 扩展依赖仍是 `internal` 契约，宿主项目无法通过公开 SDK 实现。
- `assembly.Core` 尚未完整创建和注入 Profile Binding application service。
- HTTP Profile Binding handler 在依赖缺失时只能返回 unavailable。
- 宿主业务 Profile 的读取、Identity relation 写回和事务参与方式尚未形成公开稳定协议。
- 自定义字段的组合查询、字段权限、脱敏和 module/SaaS 对等协议尚未完成。

## 3. P0：确定扩展边界

- [ ] Identity 核心字段保持固定：账号、邮箱、认证状态、密码、Token 和安全版本等。
- [ ] 客户自定义字段存放在客户自己的 Profile 对象中。
- [ ] Profile 通过唯一的 `identity_user_id` relation 关联 Identity 用户。
- [ ] 明确一个 Identity 用户是否允许绑定多个不同类型的 Profile。
- [ ] 明确同一种 Profile 的 cardinality；当前 contract 仅允许 `one_to_one`。
- [ ] 明确哪些 Profile 字段允许投影为登录 Claim；默认全部禁止。
- [ ] 明确 Profile 数据、字段 definition、binding governance 和 Identity 核心数据各自的 source owner。

## 4. P1：补齐公开 SDK 契约

- [ ] 在 `domainry-identity-sdk` 增加公开的 Profile 扩展 DTO，禁止暴露 `internal` 模型。
- [ ] 增加宿主业务 Profile 记录读取接口。
- [ ] 增加 Profile Identity relation 变更接口或等价的 transaction-aware mutation contract。
- [ ] 增加外部身份 Claim 校验接口。
- [ ] 增加重新绑定审批校验接口。
- [ ] 增加重新绑定后的会话撤销接口。
- [ ] 增加 system-managed role 解析接口。
- [ ] 为公开扩展 contract 增加版本和 capability discovery。
- [ ] 扩展接口统一接收显式 workspace、object、profile 和 actor scope。
- [ ] 定义扩展不可用、超时、冲突和不支持时的稳定 SDK 错误码。

## 5. P1：接通 module 和 standalone 装配

- [ ] 增加统一的 `HostCapabilities` 或等价公开装配对象。
- [ ] 将业务扩展能力从 `DatabaseHandle` 中拆出，`DatabaseHandle` 只表达数据库能力。
- [ ] 保留现有 `OpenWithDatabase` 的兼容适配，不破坏已有宿主。
- [ ] `module.Factory` 在 ready 前验证扩展 contract 的完整性和版本。
- [ ] 在 `assembly.Core` 中创建 `IdentityProfileBindingApplicationService`。
- [ ] 将 Profile Binding service 注入 SDK Binding 和 HTTP Handler。
- [ ] standalone 装配提供与 module 模式等价的 Profile 扩展 adapter。
- [ ] 未配置 Profile 扩展时，不发布对应 capability，或返回明确的 unsupported 错误。
- [ ] 禁止在 `Open` 完成后任意替换授权或事务相关扩展。

## 6. P1：完善 Profile Binding 流程

- [ ] 支持从宿主读取客户 Profile 记录及其自定义字段。
- [ ] 完整接通 `invite`、`claim`、`bind`、`rebind` 和 `unlink`。
- [ ] 保留当前幂等 key、request fingerprint 和 optimistic version 行为。
- [ ] Profile relation 变更、Identity binding、system-managed role 同步和事件写入保持原子性。
- [ ] 高风险重新绑定支持审批校验和旧用户会话撤销。
- [ ] Profile 不存在、已停用、黑名单、workspace 不一致或扩展不可用时 fail closed。
- [ ] relation 写回不得使用未验证的表名、字段名或 raw SQL 拼接。
- [ ] 跨 module 数据写入必须遵守对象 source owner 和 transaction owner。

## 7. P1：自定义字段管理

- [ ] 支持通过 Metadata 创建客户 Profile 对象。
- [ ] 支持新增、修改和停用 Profile 字段。
- [ ] 禁止客户直接修改 `_identity_users` 及其他 Identity 核心表。
- [ ] 字段物理存储由字段所属 module 或 Runtime 负责。
- [ ] Persistence DDL/DML 使用 `github.com/domainry/domainry-orm`。
- [ ] source-owned migration 通过宿主 migration registrar 执行。
- [ ] 所有数据库继续使用唯一 `_schema_migrations` ledger。
- [ ] 停用字段默认不执行物理 DROP，避免不可恢复的数据丢失。
- [ ] 字段类型、默认值、唯一性、索引和 validation 变化需要兼容性检查。
- [ ] 不允许自定义字段覆盖 Identity 核心字段或稳定 SDK 字段。

## 8. P1：查询和前端投影

- [ ] 保持 `IdentityUser` SDK DTO 稳定，不把客户字段动态塞进核心 DTO。
- [ ] 增加 `identity + profiles` 组合查询结果或等价 projection contract。
- [ ] 支持 Profile 摘要字段和目录筛选字段。
- [ ] 支持 Profile Tab、字段分组、自定义标签和关联对象投影。
- [ ] 支持字段级可见权限和 Profile 级 required permissions。
- [ ] 支持敏感字段隐藏、脱敏和导出限制。
- [ ] 前端必须能区分 Identity 核心字段、业务 Profile 字段和不可用字段。
- [ ] Profile 扩展失效时，Identity 核心用户详情仍可独立读取。

## 9. P2：安全与治理

- [ ] Profile object key、field key、binding key 和 relation owner 做唯一性校验。
- [ ] Identity relation 必须唯一指向 `identity_user`。
- [ ] Profile Claim 只能读取 definition 中显式声明的字段。
- [ ] Token Claim projection 使用白名单，不允许客户字段默认进入 Token。
- [ ] 所有读取和 mutation 强制校验 workspace scope。
- [ ] 管理他人 Profile Binding 必须使用精确 Action/Permission。
- [ ] self claim 不得隐式获得管理权限。
- [ ] 所有 binding mutation 写入审计和 source-owned lifecycle event。
- [ ] 扩展缺失、失败或响应不完整时禁止默认放行。
- [ ] 对扩展响应设置大小、超时和敏感数据日志限制。

## 10. P2：module/SaaS 部署一致性

- [ ] module 模式支持进程内 typed extension。
- [ ] SaaS 模式提供等价的远程协议或持久化声明式能力。
- [ ] 两种模式使用相同的 contract version、业务错误码和授权结论。
- [ ] 扩展能力加入 Binding descriptor/capability discovery。
- [ ] 不支持的扩展在启动或 discovery 阶段明确暴露。
- [ ] 禁止 SaaS 模式通过不受控反向 callback 获得宿主 ambient authority。
- [ ] remote extension 调用使用明确的 service identity、audience 和最小权限。

## 11. P2：测试

- [ ] 增加 `employee_profile` 自定义字段端到端样例。
- [ ] 覆盖 Profile 对象创建、字段新增、字段停用和冷启动恢复。
- [ ] 覆盖 Profile 读取、邀请、认领、绑定、重新绑定和解绑。
- [ ] 覆盖幂等重试、idempotency key 复用和版本冲突。
- [ ] 覆盖跨 workspace、跨 object 和跨 binding key 隔离。
- [ ] 覆盖 Profile relation 写回失败后的完整事务回滚。
- [ ] 覆盖 system-managed role 同步失败后的完整事务回滚。
- [ ] 覆盖审批拒绝、会话撤销失败和外部 Claim 校验失败。
- [ ] 覆盖 module SDK 与 HTTP transport 的合约一致性。
- [ ] 覆盖 module 与 SaaS 的业务结果和错误码一致性。
- [ ] 覆盖 SQLite、MySQL 和 PostgreSQL 方言。
- [ ] 覆盖 module 重启、metadata reload 和扩展版本不兼容。

## 12. P3：示例和文档

- [ ] 提供 `employee_profile` 示例 module。
- [ ] 提供 `employee_no`、`birthday` 和 `region` 字段示例。
- [ ] 提供 Profile Reader、relation mutation 和 Claim verifier 示例。
- [ ] 提供 module 与 SaaS 两种接入示例。
- [ ] 提供字段升级、停用、数据迁移和回滚说明。
- [ ] 明确 Identity 核心字段与客户扩展字段的所有权边界。
- [ ] 明确禁止直接修改 Identity 内部表和绕过 host migration registrar。

## 13. 完成标准

以下条件全部满足后，Identity Profile 扩展能力才可视为完成：

- 客户仅通过公开 SDK contract 和自己的 module 即可增加业务 Profile 字段。
- 客户无需 import Identity `internal` 包，也无需 fork Identity module。
- Identity 核心数据库 schema 和 SDK 用户 DTO 不因客户字段发生漂移。
- Profile Binding 所有 mutation 都具备 workspace 隔离、授权、审计、幂等和事务保证。
- module 与 SaaS 对相同输入产生一致的业务结果和错误码。
- 三种数据库方言、重启恢复和失败回滚均有自动化测试覆盖。
