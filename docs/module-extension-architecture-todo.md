# Domainry 模块扩展架构 TODO

状态：方案待实施

更新日期：2026-09-02

## 1. 范围与结论

本 TODO 覆盖 Runtime 当前模块清单中的 Identity、Notification、Integration、Scheduler、Monitoring、Data Exchange、Agent、Lifecycle、Audit、Metadata、Report，并把 Connector Provider 一并纳入扩展入口设计。

Party 模块已从当前产品拓扑和 Runtime 依赖中移除，不再作为 extension owner，也不应出现在 `ProjectExtensionSet`、模块矩阵、启动装配或 capability inventory 中。原先可能归入 Party 的客户资料、组织扩展等需求，应建模为项目/source-owned 业务对象或 Profile，再通过 Metadata、Identity binding 和窄 Fact Resolver 接入；不得为了兼容旧设计重新引入 Party SDK 依赖。

核心结论：客户代码不应修改或 fork 各模块的 `module` 包。Runtime 只提供一个项目级扩展聚合入口，每个 source module 在自己的公开 SDK 中定义强类型 `ExtensionSet`、Descriptor 和 Registry。所有扩展必须在启动阶段完成批量注册、契约校验和冻结，运行期间不得任意替换。

不能把所有扩展统一成一个万能 Hook。当前代码已经证明至少存在三种不同装配时机：

1. 启动前注册：Connector Provider、Action Handler、Agent Runner 等执行实现。
2. 模块打开后绑定：Agent、Audit、Report 的 `BindApplicationHost`，Lifecycle 的 `BindOwners`。
3. 声明式同步：Metadata Projection、Notification Catalog、Scheduler DefinitionSnapshot、Agent DefinitionSnapshot。

顶层可以统一聚合和治理，但业务接口必须继续归各 source module 所有。

## 2. 当前代码依据

- Runtime 已有两套可复用模式：`domainry-runtime/pkg/runtimeext.BusinessHandlerRegistry` 和 `domainry-connector-sdk.Registry` 都支持批量注册、重复检查、descriptor 校验和 `Freeze`。
- `domainry-runtime/pkg/runtimehost.Options` 已允许项目注入模块 Factory、Business Handler、Connector Provider、项目配置和 i18n，但还没有统一的模块业务扩展集合。
- Runtime `ModuleInventory` 已列出十一个模块，但目前只报告模块 capability、HTTP surface 和 persistence，不报告项目扩展的 owner、版本、摘要和 readiness。
- Agent、Audit、Report 已使用“先打开持久化，再绑定宿主业务能力”的两阶段装配。
- Lifecycle 已有 `OwnerExtensions`；Data Exchange 已有 Import/Export Provider；Notification 已有 Catalog、AudienceResolver、DeliveryGateway 等接口；这些能力不应推倒重做。
- Identity 的公开宿主边界仍不足以承载客户业务字段、业务 Profile 和投影规则。
- Monitoring 的 `Host` 和 `CollectHealth` 仍把 Storage、Migration、Scheduler、Lifecycle 写死，新增模块必须修改 Monitoring SDK。

## 3. 统一扩展分类

每个模块只选择自己需要的类别，不要求实现全部类别。

### A. Definition Contributor

负责声明字段、对象、模板、事件类型、调度定义、报表定义、Agent 定义等静态元数据。

- 只提交 DTO 和版本信息，不持有数据库、HTTP request 或 ambient authority。
- 通过 Metadata 或模块自己的 reconcile/sync 接口持久化。
- 支持 source owner、source ID、revision、schema hash 和停用语义。

### B. Provider / Strategy

负责需要执行代码的策略或外部实现，例如 Connector Adapter、Agent Runner、导入导出 Provider、计算函数、编码器。

- 必须有稳定 identity、contract version、revision 和 capability descriptor。
- 必须在启动时成批注册并冻结。
- 重复 key、声明能力与实际接口不一致时启动失败。

### C. Fact Resolver

负责读取其他 owner 的事实，例如业务 Profile、Identity 组织与汇报关系、通知收件人、报表数据集、Lifecycle subject。

- 使用窄接口，不暴露 store 或任意查询能力。
- 请求中显式携带 workspace、object、record、actor 和用途。
- 不得把“查到事实”直接等同于“授权通过”。

### D. Policy / Validator

负责字段校验、发送资格、保留期限、脱敏、审批、风险和 scope 判定。

- 返回结构化结论和稳定错误码。
- 安全相关扩展缺失、超时或结果不完整时 fail closed。
- 策略版本必须进入审计证据和扩展清单。

### E. Transactional Effect

负责跨 owner 的受控写入、outbox、terminal commit、relation mutation 等副作用。

- 不向扩展暴露裸数据库连接或任意事务控制。
- 由宿主拥有 transaction boundary，扩展只能使用最小 mutation capability。
- 跨 owner 写入必须通过 owner port；禁止直接写其他模块表。

### F. Projection / Surface

负责组合查询、摘要字段、Tab、OpenAPI、Action、HTTP surface 和前端展示元数据。

- 核心 SDK DTO 保持稳定；客户字段通过 projection/facet 返回。
- HTTP surface 必须先完成授权 Action 注册，再允许发布路由。
- module 与 SaaS 必须提供等价 capability 和错误语义。

### G. Lifecycle / Observation

负责 retention、subject export/erase、健康度、readiness、metrics 和 worker 状态。

- 每个 source owner 自己解释业务状态，Lifecycle/Monitoring 只聚合。
- 新增模块不应要求修改 Monitoring 的固定 `Host` 方法集合。

## 4. 项目级总入口

### P0：增加强类型聚合入口

- [ ] 在 Runtime 公共装配层增加 `ProjectExtensionFactory` 或等价入口。
- [ ] 顶层返回一个聚合 DTO，但每个字段使用所属 SDK 的强类型 `ExtensionSet`，禁止 `map[string]any`。
- [ ] 保留现有 `BusinessHandlers` 和 `Connectors` 兼容入口，内部适配到统一启动管线。
- [ ] Audit、Lifecycle、Metadata 即使暂不允许替换 Factory，也必须能接收所属 owner 的 typed contributions。
- [ ] 区分 `PreOpenProviders`、`PostOpenBindings` 和 `DefinitionContributions`，禁止依赖隐式调用顺序。

建议形态仅表达边界，不是最终 API：

```go
type ProjectExtensionSet struct {
    Identity     identitysdk.ExtensionSet
    Notification notificationsdk.ExtensionSet
    Agent        agentsdk.ExtensionSet
    Monitoring   monitoringsdk.ExtensionSet
    // 其余模块继续使用所属 SDK 类型。
}
```

### P0：统一 descriptor 和 registry 行为

- [ ] 每个可执行扩展提供 `Key`、`Owner`、`ContractVersion`、`Revision`、`Capabilities` 和可重复计算的 contract hash。
- [ ] Registry 支持原子 `RegisterExtensionSet`：整批先校验，任一失败时一个都不注册。
- [ ] Registry 检查空实现、重复 key、非法 owner、版本不兼容和 capability/interface 不一致。
- [ ] 完成 metadata、权限和宿主端口绑定后统一 `Freeze`。
- [ ] 冻结后禁止 register、replace 和 unregister。
- [ ] 扩展回调设置 timeout、并发上限、payload 大小和敏感日志限制。
- [ ] 为 unavailable、timeout、conflict、unsupported、contract mismatch 定义稳定错误码。

### P0：统一启动顺序

- [ ] 加载项目 ExtensionSet 和 descriptor。
- [ ] 校验 Runtime/SDK contract version 与 source owner。
- [ ] 注册启动前 Provider，但暂不启动 worker 和发布 HTTP route。
- [ ] 通过宿主 migration registrar 应用各 source owner 的 migrations。
- [ ] 打开模块 persistence binding。
- [ ] 同步 Metadata、权限、模板、调度、报表和 Agent definition contributions。
- [ ] Runtime 组装应用服务后执行 `BindApplicationHost` / `BindOwners`。
- [ ] 校验所有 required capability 已绑定，构建扩展 inventory 和 release digest。
- [ ] 冻结 registries，随后发布 HTTP surface 并启动 worker。
- [ ] 任一步失败都不得留下半发布 route、半启动 worker 或可变 registry。

### P1：扩展清单与运维

- [ ] 扩展 Runtime `ModuleInventory`，展示每个 module 的扩展 key、owner、revision、contract hash、capabilities 和 readiness。
- [ ] 扩展集合摘要进入 Runtime release identity，避免二进制与声明不一致。
- [ ] 健康检查报告扩展不可用，但不得输出 secret 或客户字段值。
- [ ] 支持启动时 dry-run validation，部署前发现契约冲突。

## 5. “客户加字段”的标准路径

客户字段不是向任意模块核心表加列。标准流程应为：

1. 项目声明一个 source-owned 业务对象或 Profile/Facet 对象及字段。
2. Metadata 保存字段 definition、标签、字典、权限和 UI 投影。
3. 字段所属 owner 使用 `domainry-orm` 管理 DDL/DML；source-owned migration 通过宿主 registrar，数据库仍只有 `_schema_migrations`。
4. Identity 只保存稳定 relation/binding，或通过公开 Fact Resolver 读取关联事实。
5. 查询层返回“核心 DTO + 扩展 projection”，不向 `IdentityUser` 等稳定 DTO 动态塞字段。
6. 写入通过字段 owner 的 mutation contract，并受 workspace、授权、审计、幂等和事务边界约束。
7. 字段停用默认只停止使用，不直接物理 DROP。

## 6. 各模块切入点矩阵

| 模块 | 当前已有入口 | 需要补齐的主要切入点 | 优先级 |
| --- | --- | --- | --- |
| Runtime | `runtimeext`、Connector registry、Factory 注入、project config/i18n | 项目级 typed ExtensionSet、统一启动阶段、freeze、inventory、release digest | P0 |
| Identity | OrganizationScopeResolver、BusinessProfileResolver、module Action provider | Profile/Facet definition、record reader、relation mutation、binding policy、record-scope policy、认证 Provider registry、projection | P0 |
| Monitoring | 固定 Identity/Storage/Migration/Scheduler/Lifecycle/Metrics Host | 通用 ObservationContributor registry、readiness/metrics 分类、owner 隔离 | P0 |
| Agent | 丰富的 ApplicationHost，definition sync | Runner/模型 Provider registry、context contributor、guardrail/approval policy；复用现有工具调用 Host | P1 |
| Audit | ApplicationHost 的 principal/authorize/project，Appender/Reader/Exporter | retention policy、append enrichment/redaction、export encoder、archive sink/integrity policy | P1 |
| Integration/Connector | ProviderDescriptor、ProviderSet、Registry/Freeze、secret cipher、trigger sink | 移除 Integration 对 built-in connector catalog 的直接硬编码；统一 catalog contribution 和 provider inventory | P1 |
| Notification | Catalog、AudienceResolver、RecipientDirectory、DeliveryGateway、template validator | 把 monolithic Host 拆成可版本化 contribution；发送资格/consent policy、routing/retry policy、可选能力协商 | P1 |
| Lifecycle | `OwnerExtensions`、OwnerLifecycleExecutor、SubjectExecutionHandler、artifact ports | owner registry 的去重/版本/freeze；确保所有模块按 owner 注册 retention 和 subject 能力 | P1 |
| Metadata | Definition/Localization/Dictionary、Projection.Sync | source contribution descriptor、resource-type validator、projection reconcile receipt、停用和冲突治理 | P1 |
| Data Exchange | Import/Export/Artifact/Planning/Completion Provider | 保留现有 provider 模型；补 descriptor registry、freeze、inventory 和项目装配入口 | P1 |
| Report | DatasetReader、ObjectSQLExecutor、ExportGateway、late host binding | 确有需求时增加纯函数 calculation/analysis registry；格式输出优先委托 Data Exchange | P2 |
| Scheduler | DefinitionProvider、Dispatcher、HTTPConnectionProvider | 先标准化 definition contribution；仅在出现第三类 target/schedule 需求时增加 typed adapter registry | P2 |

## 7. 模块专项 TODO

### 7.1 Identity

- [ ] 执行 `identity-extension-todo.md` 中的 Profile Binding 和自定义字段计划。
- [ ] 将 Profile 扩展 DTO、Reader、relation mutation、claim verifier、approval/session revocation 暴露到 `domainry-identity-sdk`。
- [ ] 把当前硬编码为允许的 `RecordScopeAllows` 替换为必需的授权策略，缺失时 fail closed。
- [ ] 将当前固定 `CallbackAdapter` 演进为经过 descriptor 校验的认证 Provider registry；内置 OIDC/SAML 作为 builtin provider 注册。
- [ ] `DatabaseHandle` 只表达数据库借用，业务扩展迁移到独立 Host/Extension contract。
- [ ] module 与 SaaS 使用同一 Profile capability descriptor 和错误码。

### 7.2 Monitoring

- [ ] 用 `ObservationContributor{Owner, Kind, Observe}` 替换固定 Scheduler/Lifecycle 方法。
- [ ] Storage 和 Migration 的启动 readiness 可以保留强类型核心接口，其余业务模块通过 registry 贡献 health/metrics。
- [ ] contributor 单独超时和错误隔离，一个模块失败不能阻断其他模块观测。
- [ ] 输出按 owner 稳定排序并限制 payload 大小。
- [ ] 新增模块时只注册 contributor，不再修改 Monitoring SDK Host。

### 7.3 Agent

- [ ] 将 module factory 中固定的 HTTP runner 配置抽象为 `RunnerProvider` registry。
- [ ] 内置 runner 通过同一 registry 注册，不保留特殊旁路。
- [ ] 增加 ContextContributor，输入必须包含 principal、workspace、agent/task 和用途。
- [ ] 增加 Guardrail/ApprovalPolicy，结论进入 task/proposal 审计。
- [ ] 工具和 workflow 执行继续走现有 ApplicationHost，不重复建立一个绕过授权的 tool registry。
- [ ] Runner、context、guardrail capability 在 module/SaaS descriptor 中可发现。

### 7.4 Audit

- [ ] 把固定 business/governance/operations retention 天数改为版本化 RetentionPolicy。
- [ ] 增加 append-time EventEnricher 和 RedactionPolicy；禁止扩展移除必需审计字段。
- [ ] 保留现有 `ProjectAuditEvents` 作为读取投影，不让它承担写入期治理。
- [ ] 将固定 CSV 导出抽象为受控 ExportEncoder；编码器不得改变授权后的事件集合。
- [ ] 增加 ArchiveSink/IntegrityPolicy 时保持 Audit 为 evidence owner。
- [ ] 策略版本、redaction 结论和导出格式进入审计证据。

### 7.5 Integration 与 Connector

- [ ] 以 Connector Registry 作为所有 Provider Registry 的参考实现。
- [ ] Integration 不再直接依赖 `domainry-connectors/catalog.Definitions()` 的特殊路径；builtin 和 project provider 都产出统一 catalog contribution。
- [ ] ProviderDescriptor 同时驱动配置字段、secret 字段、operation、reliability 和 capability inventory。
- [ ] 保留 Registry 的原子批量注册、duplicate check、optional capability 校验和 freeze。
- [ ] process transport 继续受 Runtime allowlist policy 限制，扩展声明不得自行放宽。

### 7.6 Notification

- [ ] 保留 Catalog、AudienceResolver、RecipientDirectory、DeliveryGateway、DeliveryMetrics 和 ProviderTemplateValidator。
- [ ] 把 Catalog 拆成带 source owner/revision 的 contribution set，支持确定性合并和重复 key 检查。
- [ ] 区分 required 与 optional capability，避免所有宿主被迫实现无关接口。
- [ ] 增加 DeliveryEligibilityPolicy，消费业务 Profile/Identity 提供的 consent/preference facts，但由 Notification 决定发送结论。
- [ ] 增加受控 Routing/RetryPolicy；不得允许项目代码直接操纵 worker lease 或持久化状态。
- [ ] template、event type、rule、channel 和 provider capability 全部进入 inventory。

### 7.7 Lifecycle

- [ ] 将 `OwnerExtensions` 的 executors/handlers 转为按 owner 注册的 registry。
- [ ] 检查重复 owner、声明能力与接口不一致、subject resolver 冲突。
- [ ] 在所有 owner 注册完成后一次性 bind/freeze，再启动 retention worker。
- [ ] 每个持久化业务模块明确是否提供 retention、subject preview/export/erase 和 artifact cleanup。
- [ ] 不允许 Lifecycle 直接查询或删除其他 owner 的表。

### 7.8 Metadata

- [ ] `Projection.Sync` 增加 source descriptor、revision、schema hash 和 reconcile receipt。
- [ ] 增加 resource-type validator registry；validator 只校验所属资源，不执行业务写入。
- [ ] 定义同 key 多 source 冲突、source 停用、回滚和冷启动恢复语义。
- [ ] 字段、字典、i18n、UI projection 保持声明式，不把 Go callback 序列化进 Metadata。
- [ ] Metadata 只保存定义和投影，不拥有 Identity 或业务 Profile 客户字段的业务值。

### 7.9 Data Exchange

- [ ] 给现有 Import/Export Provider 增加统一 descriptor、contract version 和 revision。
- [ ] Provider 注册成批校验并冻结，禁止 job 运行期间替换。
- [ ] Artifact Provider 继续作为 canonical bundle 的旁路，不强迫所有格式转换为 CSV rows。
- [ ] Planning/Completion/Projector 等 optional capability 必须与 descriptor 一致。
- [ ] Provider inventory 展示支持的 object、方向、artifact 模式和限制。

### 7.10 Report

- [ ] 保留当前 DatasetReader、ObjectSQLExecutor、SourceVersionReader、ExportAuthorization、SnapshotTerminalCommitter 和 ExportGateway。
- [ ] 先通过 Report definition 扩展数据源、维度、指标和分析，不为普通字段需求增加 Go Hook。
- [ ] 若客户确需自定义聚合，增加 deterministic/pure `CalculationProvider`，并限制输入输出类型、资源消耗和版本。
- [ ] SQL pushdown 必须由 Report 编译并经 host authorize，Provider 不得提交请求方编写的任意 SQL。
- [ ] CSV/XLSX/PDF 等 artifact 格式优先通过 Data Exchange provider 扩展，Report 不重复管理文件生命周期。

### 7.11 Scheduler

- [ ] 将 DefinitionSnapshot 纳入统一 source contribution 和 reconcile receipt。
- [ ] 保留 Dispatcher 作为业务执行边界，Scheduler 不理解下游 owner 业务。
- [ ] 当前 `runtime_operation` 和 `http` target 足以承载大多数项目扩展，先不开放任意 target callback。
- [ ] 只有出现不能由现有 target 表达的明确需求时，再增加带 descriptor 的 TargetAdapter。
- [ ] 新 schedule type 必须定义 preview、timezone、misfire、catch-up 和幂等 window 语义后才能注册。

## 8. 数据、事务与迁移约束

- [ ] 每个数据库继续只有宿主拥有的 `_schema_migrations`。
- [ ] Embedded module 的 source-owned migrations 必须通过 host migration registrar。
- [ ] DDL/DML 使用 `github.com/domainry/domainry-orm`；无等价能力时才允许局部 raw SQL，并补方言测试和理由。
- [ ] 客户扩展表由客户/source owner 命名和维护，不给模块核心表直接加客户列。
- [ ] 扩展代码不获得关闭宿主数据库、提交宿主事务或访问任意 owner 表的能力。
- [ ] transaction-aware extension 必须支持幂等、回滚、fencing/乐观锁和 crash recovery。
- [ ] module 与 SaaS 模式使用等价协议；SaaS callback 使用 service identity、audience 和最小权限。

## 9. 测试 TODO

- [ ] Registry 原子批量注册、重复 key、版本不兼容、capability/interface 不一致和 freeze 测试。
- [ ] 启动任一阶段失败时 route、worker、registry 和 migration 状态测试。
- [ ] Embedded 与 SaaS 对相同扩展输入的 capability、结果和稳定错误码一致性测试。
- [ ] 多 workspace、跨 owner、越权、超时、panic、超大 payload 和敏感日志测试。
- [ ] 自定义字段定义、写入、查询、停用、冷启动恢复和回滚测试。
- [ ] source-owned migration 在 SQLite、MySQL、PostgreSQL 上共用 `_schema_migrations` 的测试。
- [ ] extension inventory、release digest、部署漂移和不兼容升级测试。
- [ ] 每个模块至少提供一个最小示例 extension，并有 contract test suite。

## 10. 实施顺序

### P0：先打通骨架

- [ ] 定义公共 descriptor/registry 约束和 Runtime ProjectExtensionSet。
- [ ] 把现有 runtimeext 与 Connector 接入统一启动和 inventory，不改变现有调用方。
- [ ] 打通 Identity Profile 和 Monitoring Observation 两个最明显缺口。
- [ ] 完成启动阶段、freeze、release digest 和失败回滚。

### P1：迁移已有扩展口

- [ ] 将 Notification、Lifecycle、Data Exchange 的既有接口包装成 versioned contribution registry。
- [ ] 增加 Agent Runner、Audit policy、Integration catalog contribution。
- [ ] 完成 Metadata source reconcile 和各模块 lifecycle/observation 注册。

### P2：按真实需求增加策略型扩展

- [ ] 评估 Report custom calculation 的真实用例后再开放。
- [ ] 评估 Scheduler 第三类 target/schedule type 的真实用例后再开放。
- [ ] 不为“可能会用”提前开放任意代码执行、任意 SQL 或任意数据库访问。

## 11. 完成标准

- 客户可以只修改自己的项目/module，通过公开 SDK 增加字段、Profile、Provider、策略或观测，不需要 fork Domainry module。
- 所有扩展都能回答“谁拥有、什么版本、何时注册、需要什么能力、失败如何处理、是否已冻结”。
- 核心 DTO 和核心表不会因为客户字段发生不受控漂移。
- 扩展不能绕过 workspace、授权、审计、事务、migration ledger 和 source-owner 边界。
- module 与 SaaS 能力可发现、行为和错误码一致。
- Runtime inventory 和 release identity 可以准确证明当前运行的模块及扩展集合。
