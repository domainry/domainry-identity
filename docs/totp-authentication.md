# 验证码应用接入

Identity 内置 `domainry_totp` 验证器，支持 RFC 6238 的 SHA-1、6 位数字、30 秒周期；苹果「密码」通过 `apple-otpauth://totp/` 设置链接或手动设置密钥绑定，其他兼容应用可使用返回的 `otpauth://totp/` URI。

绑定只更换现有 PIN 挑战的验证方式。登录是否需要 PIN 仍由现有已验证 OTP 因子及 provider purpose 决定；绑定本身不会新增登录 MFA 要求。操作验证继续由 Runtime 的 Action assurance 策略触发，普通操作直接执行。已绑定时，Identity 优先返回 TOTP 挑战，不依赖短信提供方或手机号码。

## 自助接口

`POST /auth/totp` 从已验证的 Bearer Token 推导用户和 Workspace，不接受客户端指定这两个字段。独立服务同时通过 `/browser/auth/totp` 暴露 Browser Gateway；Runtime 内嵌模块使用 `/auth/totp`。SDK 使用可选的 `TOTPManager` 扩展，旧的 `CredentialManager` 实现不必新增方法。

| operation | 请求字段 | 行为 |
| --- | --- | --- |
| `status` | 无 | 只返回 `enabled` |
| `enroll` | `current_password` | 校验密码后生成待确认绑定，返回 `state`、`setup_key`、`otpauth_url`、`expires_at` |
| `confirm` | `state`、`code` | 第一枚有效动态码确认绑定 |
| `disable` | `current_password`、`code` | 校验密码和未使用的动态码后解绑并清除密钥 |

待确认绑定有效期 5 分钟。已生效绑定无法被直接覆盖；重新生成待确认绑定会使旧的待确认挑战失效。状态查询和确认结果不会再次返回设置密钥，HTTP 响应禁止缓存。绑定管理在应用层统一记录审计，不记录密码、设置密钥或动态码。

登录和操作验证沿用原有接口，挑战的 `provider` 为 `domainry_totp`、`type` 为 `totp`。客户端应提示用户读取验证码应用，不显示发送或重发按钮。输入框使用 `autocomplete="one-time-code"`。

## 存储与恢复

Identity schema `011_totp_authentication` 在 `_identity_mfa_factors` 增加加密密钥、已使用时间步、失败次数和锁定截止时间。沿用 Identity 的加密密钥提供方及宿主 migration ledger；不增加 Runtime 自有表。

验证接受当前时间步及相邻一步。因子更新与挑战消费处于同一事务，已成功使用的时间步不能在另一挑战中再次使用；失败预算也在挑战之间共享，达到现有最大尝试数后锁定 5 分钟。挑战分别约束绑定、登录、操作和解绑用途，并绑定 Workspace、用户及绑定代次。

无法访问验证码应用时，管理员使用现有 MFA 因子撤销流程恢复，用户随后重新绑定。本次不增加恢复码或新的登录验证策略。

## 验证证据

- `internal/domain/auth/policy/auth_totp_test.go`：RFC 时间向量、格式、时钟偏差与重复使用。
- `internal/infrastructure/persistence/database/auth/auth_totp_store_test.go`：SQLite 加密存储、作用域和用途隔离、因子撤销、共享失败预算。
- `internal/infrastructure/persistence/database/auth/auth_totp_flow_test.go`：密码、绑定、原登录规则、动态码登录与操作保证凭据。
- `internal/transport/http/server/totp_gateway_test.go`、`module/factory_test.go`：真实 HTTP 接口、Browser Gateway 和内嵌模块路由。
- Plane 的 `tests/e2e/totp.spec.ts`：绑定、持久化、解绑、登录，以及普通和受保护操作的浏览器交互；尚未进行苹果设备实机绑定验收。
