# 雨云代理商用户资源平台

基于 Quarkus、Qute 和 PostgreSQL 的代理商客户绑定、资源清单与 OAuth2 授权服务。

> 注意：本项目为自用测试构建，生产环境使用请自行评估后使用。

## 功能

- 客户提交雨云 API Key；平台请求雨云 `GET /user/`，校验 `data.ID`、`data.Inviter`、实名状态和微信绑定状态。仅接受 `Inviter` 精确等于代理商 UID、实名字段明确为通过且 `WechatOpenID` 非空的账号。
- API Key 使用 AES-GCM 加密后保存。后台和 OAuth 接口不会返回该 Key。
- 管理端可查看已绑定客户、停用客户、读取 RCS/RGS/ROS 实例清单，并登记/停用第三方 OAuth2 客户端。
- OAuth2 授权码流程支持 PKCE `S256`、机密客户端和公共客户端、短期不透明 Bearer Token、UserInfo 和 Token Revocation。
- 资源清单做字段白名单投影，不展示实例密码、对象存储 AK/SK 等凭据。

本项目暂时只读取资源清单，不会通过保存的客户 API Key 执行购买、重装、续费、删除等资源变更操作。

## 雨云接口依据

两个参考 Go SDK 都使用 `https://api.v2.rainyun.com`、`x-api-key` 请求头和 `GET /user/`；用户信息结构中含 `ID`、`Name`、`Email`、`Inviter`、`Certify`、`CertifyStatus` 和 `WechatOpenID`。本平台只接受 `Certify=1` 或明确的通过状态标签（例如实测到的 `passed`），微信要求 `WechatOpenID` 非空；未知状态按未通过处理。SDK 文档没有定义 `Inviter` 在所有场景下是否等价于当前代理商关系。上线前应使用代理商及其下级客户的实际账号响应确认这个字段语义与 UID 值；平台按直接 UID 精确匹配，不做模糊推断。

## 本地开发

需要 Java 21。开发模式默认使用内存 H2 数据库：

```sh
./mvnw quarkus:dev
```

首次启动前生成初始管理员密码哈希（之后可在管理后台修改）：

```sh
export APP_ADMIN_USERNAME="admin"
export APP_ADMIN_PASSWORD_HASH="$(python3 scripts/hash-password.py)"
```

`scripts/hash-password.py` 会通过终端安全读取管理员密码并输出 PBKDF2-SHA256 哈希。不要把真实密钥写进 Git 或提交到仓库。

## 生产部署

生产配置使用 PostgreSQL。仅数据库配置和首次初始化管理员账号需要通过环境变量提供，其余运行时配置（代理商 UID、雨云 API 地址与超时、对外根地址、Cookie Secure、Session 密钥、API Key 加密主密钥）均在首次启动时初始化并持久化到数据库，可通过管理后台 `/admin/settings` 修改：

| 环境变量 | 用途 |
| --- | --- |
| `DATABASE_URL` | JDBC URL，例如 `jdbc:postgresql://db:5432/rainyun_agent` |
| `DATABASE_USER` / `DATABASE_PASSWORD` | 数据库凭据 |
| `APP_ADMIN_USERNAME` | 首次初始化的管理员账号（数据库已有管理员后忽略） |
| `APP_ADMIN_PASSWORD_HASH` | 首次初始化的管理员 PBKDF2-SHA256 哈希（数据库已有管理员后忽略） |

Session 密钥和 API Key 加密主密钥会在首次启动时自动生成并保存到数据库；如需在后台轮换加密主密钥，系统会在同一事务中自动重新加密已保存的客户 API Key。数据库备份仍应加密保存。

```sh
./mvnw package -DskipTests
java -Dquarkus.profile=prod -jar target/quarkus-app/quarkus-run.jar
```

可用 `/q/health/ready` 检查服务就绪状态。首次生产启动会由 Flyway 创建数据库表。

## OAuth2 接口

发现文档：`/.well-known/oauth-authorization-server`

授权请求参数：

- `response_type=code`
- `client_id`
- 已登记的完整 `redirect_uri`
- `scope=profile email`（按需选择）
- 调用方生成的 `state`
- `code_challenge` 和 `code_challenge_method=S256`（必填）

授权码在 3 分钟后过期且只能兑换一次。访问令牌只保存 SHA-256 哈希，1 小时过期。机密客户端在 Token 请求中使用 HTTP Basic 或表单客户端认证；公共客户端使用 `client_id` 且不发送密钥。两类客户端都必须校验 PKCE。

```text
GET  /oauth/authorize
POST /oauth/token
GET  /oauth/userinfo       Authorization: Bearer <access_token>
POST /oauth/revoke
```

UserInfo 的 `sub` 是雨云 UID；`name` 需要 `profile` Scope，`email` 需要 `email` Scope。该服务提供 OAuth2 UserInfo 风格接口，不宣称实现 OpenID Connect，也不签发 ID Token。

## 数据保护说明

- Rainyun API Key 只在服务端校验/查询雨云 API，并用 AES-GCM 存储。
- 管理员口令用 PBKDF2-HMAC-SHA256（310,000 次迭代）校验；OAuth 客户端密钥也以同类哈希保存。
- Session Cookie 使用 HMAC-SHA256、`HttpOnly`、`SameSite=Lax` 和配置化 `Secure` 属性。
- OAuth 客户端回调只允许 HTTPS、localhost HTTP 或登记的私有应用 URI Scheme；redirect URI 必须完全匹配登记值。
- 用户授权后第三方仅取得短期 Bearer Token；没有 API Key、云主机密码或控制面板凭据的 Scope。
