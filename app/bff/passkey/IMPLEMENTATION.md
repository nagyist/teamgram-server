# Passkey BFF 实现说明

本文档描述 Teamgram passkey BFF 服务端的实现：配置、存储、RPC 接口与调用流程。

## 目录结构

```
app/bff/passkey/
├── README.md              # Passkey 产品介绍与使用说明
├── IMPLEMENTATION.md      # 本实现文档
├── etc/passkey.yaml       # 服务配置
├── internal/
│   ├── config/            # 配置定义（KV、AuthsessionClient、UserClient、DcId）
│   ├── dao/               # 存储与 RPC 客户端（Redis passkey 存储、authsession、user）
│   ├── core/              # 业务逻辑
│   │   ├── webauthn_options.go   # WebAuthn 选项生成与 userHandle 解析
│   │   ├── account.*_handler.go # account 相关 RPC 实现
│   │   └── auth.*_handler.go    # auth 相关 RPC 实现
│   ├── server/            # gRPC 服务入口
│   └── svc/               # 服务上下文（Config + Dao）
├── client/                # 客户端封装（供 bff 代理调用）
└── cmd/passkey/           # 主程序
```

## 配置

`internal/config/config.go` 与 `etc/passkey.yaml`：

| 配置项 | 说明 |
|--------|------|
| `KV` | Redis 连接，用于存储 passkey 与 challenge |
| `AuthsessionClient` | authsession 服务（用于 finishPasskeyLogin 绑定 authKey 与 userId） |
| `UserClient` | user 服务（用于 finishPasskeyLogin 拉取用户信息） |
| `DcId` | 当前 DC ID，用于生成 userHandle 格式 `dcId:userId` |

## 存储（Redis）

由 `internal/dao` 实现，键值约定如下：

| Key 格式 | 说明 |
|----------|------|
| `passkey_reg_challenge:{authKeyId}` | 注册流程的 session（challenge、userId、dcId、optionsJSON） |
| `passkey_login_challenge:{authKeyId}` | 登录流程的 session（challenge） |
| `passkey_cred:{credentialId}` | 单个 passkey 信息（StoredPasskey JSON） |
| `passkey_user:{userId}` | 用户拥有的 credentialId 列表（逗号分隔） |

**StoredPasskey 字段**：`Id`、`Name`、`UserId`、`DcId`、`Date`、`LastUsageDate`、`PublicKeyB64`（预留）。

## RPC 接口与实现

### Account（需已登录，使用 `c.MD.UserId`）

| 方法 | 说明 |
|------|------|
| **account.getPasskeys** | 返回当前用户所有 passkey 列表（`Account_Passkeys`）。 |
| **account.deletePasskey** | 校验 passkey 归属后从存储删除，返回 `Bool`。 |
| **account.initPasskeyRegistration** | 生成 32 字节 challenge 与 Creation Options（rp、user.id=`dcId:userId`、pubKeyCredParams），写入 `passkey_reg_challenge`，返回 `Account_PasskeyRegistrationOptions`（options.data 为含 `publicKey` 的 JSON）。 |
| **account.registerPasskey** | 校验 credential 类型为 PublicKey + ResponseRegister，将 passkey 写入 `passkey_cred` 与 `passkey_user`，返回 `Passkey`。当前未做 attestation 密码学校验。 |

### Auth（登录流程，可能未登录）

| 方法 | 说明 |
|------|------|
| **auth.initPasskeyLogin** | 生成 challenge 与 Assertion Options（空 `allowCredentials`，依赖客户端 resident key），写入 `passkey_login_challenge`，返回 `Auth_PasskeyLoginOptions`。 |
| **auth.finishPasskeyLogin** | 校验 credential 类型为 PublicKey + ResponseLogin，从 `userHandle` 解析 `dcId:userId`，用 credentialId 查存储并校验归属，调用 authsession 的 `AuthsessionBindAuthKeyUser` 绑定当前 authKey 与 userId，拉取用户后返回 `Auth_Authorization`。 |

## 与客户端的约定

- **注册**：服务端返回的 `options.data` 为 JSON，客户端解析 `publicKey` 作为 CreatePublicKeyCredentialRequest；注册时 `user.id` 使用 `dcId:userId`，以便登录时从 assertion 的 userHandle 带回。
- **登录**：服务端返回的 options 含 `publicKey`（challenge、rpId、空 allowCredentials）；客户端完成 GetCredential 后，在 finishPasskeyLogin 中上传的 response 的 `userHandle` 为字符串 `"datacenterId:userId"`。
- **Session**：`app/interface/session` 在收到 `TLAuthFinishPasskeyLogin` 成功且结果为 `Auth_Authorization` 时，会调用 `changeAuthState(ctx, AuthStateNormal, userId)` 更新登录状态。

## 错误返回

- 未登录访问 account 接口：`status.Error(ErrUnauthorized, "AUTH_KEY_UNREGISTERED")`。
- 参数/类型错误：`status.Error(ErrBadRequest, "INPUT_CONSTRUCTOR_INVALID" | "PASSKEY_ID_INVALID" | "PASSKEY_NOT_FOUND" | "PASSKEY_CREDENTIAL_INVALID")`。
- 内部错误：`mtproto.ErrInternalServerError`。

## 安全说明

当前实现**未做** attestation（注册）与 assertion（登录）的密码学校验，仅做 credential 存在性与 userHandle 归属校验。生产环境建议接入 [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) 做完整 WebAuthn 校验。

## 构建与运行

```bash
# 构建
make passkey
# 或
go build -o teamgramd/bin/passkey ./app/bff/passkey/cmd/passkey

# 运行（需先配置 etc/passkey.yaml 中的 Redis、Authsession、User 等）
./teamgramd/bin/passkey -f=teamgramd/etc/passkey.yaml
```

依赖基础设施：Redis、authsession 服务、biz（user）服务；部署时需在 bff 代理中注册 passkey 服务的路由（如 `/tg.RPCPasskey/`）。

## 部署在 teamgram.net 的 assetlinks.json

Passkey / App Links 依赖 Relying Party ID 为 **teamgram.net**，与 Android 的 Digital Asset Links 需一致。

- **存放位置**：将 `app/bff/passkey/assetlinks.json` 部署为 **https://teamgram.net/.well-known/assetlinks.json**（需 HTTPS、Content-Type: `application/json`）。
- **修改内容**：将 `sha256_cert_fingerprints` 中的 `REPLACE_WITH_YOUR_APP_SHA256_FINGERPRINT` 替换为实际签名证书的 SHA-256 指纹（可多个：正式/调试）。若 Android 包名不是 `org.telegram.messenger`，请同步修改 `package_name`。
- **获取指纹**：  
  `keytool -list -v -keystore your.keystore -alias your_alias` 或  
  `apksigner verify --print-certs your.apk`  
  取 “SHA-256” 一行，格式为冒号分隔十六进制（如 `AB:CD:...`）。
