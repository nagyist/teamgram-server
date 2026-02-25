# Passkey / WebAuthn 示例

本目录为 Teamgram Passkey BFF 的 WebAuthn 示例，使用 **@simplewebauthn** 实现无密码注册和登录，包含可运行的 Node 服务与前端页面。

- 后端：Node.js + Express
- 前端：HTML + JavaScript
- 关键配置说明（RP ID、Origin 等）

RP ID 必须与访问的域名匹配（例如使用 `localhost` 时，RP ID 应设为 `localhost`）。

---

## 1. 目录结构

```
app/bff/passkey/examples/
├── README.md           # 本文件：说明与运行指南
├── package.json        # 依赖（在 examples 根目录执行 npm install）
└── project/            # 可运行示例
    ├── server.js       # 后端（Express + @simplewebauthn/server）
    └── public/
        └── index.html  # 前端页面
```

---

## 2. 快速运行

### 方式一：在 project 目录运行（推荐）

```bash
# 进入示例项目
cd app/bff/passkey/examples/project

# 安装依赖（若未安装）
npm install express body-parser @simplewebauthn/server

# 启动服务
node server.js
```

### 方式二：在 examples 目录安装依赖后运行

```bash
cd app/bff/passkey/examples
npm install
cd project
node server.js
```

### 访问与测试

1. 浏览器打开：**http://localhost:3000**
2. **注册**：输入用户名，点击「注册通行密钥」，按提示完成生物识别/安全密钥。
3. **登录**：输入同一用户名，点击「登录」，使用刚注册的通行密钥完成登录。

### 环境要求

- Node.js 14+
- 支持 WebAuthn 的浏览器（Chrome、Edge、Safari、Firefox 等）
- 本地访问时 RP ID 为 `localhost`；若用 IP 访问，需在 `server.js` 中把 `rpID` 和 `expectedOrigin` 改为对应 IP 和端口。

---

## 3. 后端实现 (server.js)

本示例兼容 **@simplewebauthn/server** 新版 API：`userID` 使用 `Uint8Array`、`generateRegistrationOptions`/`generateAuthenticationOptions` 为异步需 `await`、`registrationInfo.credential` 结构、`allowCredentials[].id` 为 base64url 字符串。

```javascript
const crypto = require('crypto');
const express = require('express');
const bodyParser = require('body-parser');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); // 托管前端静态文件

// 临时内存存储（生产环境应使用数据库）
const users = {};
const rpID = 'localhost';
const expectedOrigin = 'http://localhost:3000';

function findUser(userHandle) {
  return users[userHandle];
}
function saveUser(user) {
  users[user.id] = user;
}

// WebAuthn 要求 userID 为 Uint8Array，最多 64 字节
function toWebAuthnUserID(username) {
  const hash = crypto.createHash('sha256').update(username, 'utf8').digest();
  return new Uint8Array(hash);
}

// ---------- 1. 注册：生成注册选项 ----------
app.post('/generate-registration-options', async (req, res) => {
  const { username } = req.body;
  const userHandle = `user_${username}`;
  const userID = toWebAuthnUserID(username);

  const options = await generateRegistrationOptions({
    rpID,
    rpName: 'Example App',
    userID,
    userName: username,
    attestationType: 'none',
    supportedAlgorithmIDs: [-7, -257],
  });

  const user = findUser(userHandle) || { id: userHandle, username, devices: [] };
  user.currentChallenge = options.challenge;
  saveUser(user);
  res.json(options);
});

// ---------- 2. 注册：验证认证器响应 ----------
app.post('/verify-registration', async (req, res) => {
  const { username, attestationResponse } = req.body;
  const user = findUser(`user_${username}`);
  if (!user) return res.status(400).json({ error: 'User not found' });

  try {
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      const { credential } = verification.registrationInfo;
      user.devices.push({
        credentialPublicKey: Buffer.from(credential.publicKey).toString('base64'),
        credentialID: credential.id, // base64url 字符串
        counter: credential.counter,
      });
      delete user.currentChallenge;
      saveUser(user);
      return res.json({ verified: true });
    }
    return res.status(400).json({ verified: false, error: 'Verification failed' });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error: error.message });
  }
});

// ---------- 3. 登录：生成认证选项 ----------
app.post('/generate-authentication-options', async (req, res) => {
  const { username } = req.body;
  const user = findUser(`user_${username}`);
  if (!user || user.devices.length === 0) {
    return res.status(400).json({ error: 'User not registered or no devices' });
  }

  const allowCredentials = user.devices.map(dev => ({
    id: dev.credentialID,
    type: 'public-key',
  }));

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: 'preferred',
  });
  user.currentChallenge = options.challenge;
  saveUser(user);
  res.json(options);
});

// ---------- 4. 登录：验证认证器断言 ----------
app.post('/verify-authentication', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const user = findUser(`user_${username}`);
  if (!user) return res.status(400).json({ error: 'User not found' });

  const device = user.devices.find(dev => dev.credentialID === assertionResponse.id);
  if (!device) return res.status(400).json({ error: 'Credential not found' });

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      credential: {
        id: device.credentialID,
        publicKey: Buffer.from(device.credentialPublicKey, 'base64'),
        counter: device.counter,
      },
    });

    if (verification.verified) {
      device.counter = verification.authenticationInfo.newCounter;
      delete user.currentChallenge;
      saveUser(user);
      return res.json({ verified: true });
    }
    return res.status(400).json({ verified: false, error: 'Authentication failed' });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error: error.message });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
```

---

## 4. 前端页面 (public/index.html)

```html
<!DOCTYPE html>
<html>
<head>
  <title>WebAuthn 示例</title>
  <script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.umd.min.js"></script>
</head>
<body>
  <h1>WebAuthn 无密码登录示例</h1>

  <div>
    <h2>注册</h2>
    <input type="text" id="reg-username" placeholder="用户名" />
    <button onclick="register()">注册通行密钥</button>
  </div>

  <div>
    <h2>登录</h2>
    <input type="text" id="auth-username" placeholder="用户名" />
    <button onclick="authenticate()">登录</button>
  </div>

  <div id="message"></div>

  <script>
    const apiBase = 'http://localhost:3000';

    async function register() {
      const username = document.getElementById('reg-username').value;
      if (!username) return alert('请输入用户名');

      try {
        // 1. 从服务器获取注册选项
        const optionsRes = await fetch(`${apiBase}/generate-registration-options`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username }),
        });
        const options = await optionsRes.json();

        // 2. 调用浏览器 API 创建凭证
        const attestationResponse = await SimpleWebAuthnBrowser.startRegistration(options);

        // 3. 将响应发送到服务器验证
        const verifyRes = await fetch(`${apiBase}/verify-registration`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, attestationResponse }),
        });
        const verifyResult = await verifyRes.json();
        if (verifyResult.verified) {
          document.getElementById('message').innerText = '注册成功！';
        } else {
          document.getElementById('message').innerText = '注册失败：' + (verifyResult.error || '未知错误');
        }
      } catch (error) {
        console.error(error);
        document.getElementById('message').innerText = '注册出错：' + error.message;
      }
    }

    async function authenticate() {
      const username = document.getElementById('auth-username').value;
      if (!username) return alert('请输入用户名');

      try {
        // 1. 获取认证选项
        const optionsRes = await fetch(`${apiBase}/generate-authentication-options`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username }),
        });
        const options = await optionsRes.json();

        // 2. 调用浏览器 API 获取断言
        const assertionResponse = await SimpleWebAuthnBrowser.startAuthentication(options);

        // 3. 发送给服务器验证
        const verifyRes = await fetch(`${apiBase}/verify-authentication`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, assertionResponse }),
        });
        const verifyResult = await verifyRes.json();
        if (verifyResult.verified) {
          document.getElementById('message').innerText = '登录成功！';
        } else {
          document.getElementById('message').innerText = '登录失败：' + (verifyResult.error || '未知错误');
        }
      } catch (error) {
        console.error(error);
        document.getElementById('message').innerText = '登录出错：' + error.message;
      }
    }
  </script>
</body>
</html>
```

---

## 5. 关键点说明

### RP ID 和源（Origin）

- **`rpID`**：在服务端设置为 `'localhost'`，因为前端访问的是 `http://localhost:3000`，RP ID 必须是网站的**有效注册域后缀**，所以 `localhost` 是允许的（对于 IP 也同理）。如果部署到生产环境，`rpID` 应设置为你的域名（例如 `example.com`）。
- **`expectedOrigin`**：必须完全匹配前端协议+域名+端口，用于验证响应来源。本例为 `http://localhost:3000`。

### Android 原生应用注意事项

如果你的应用是 Android 原生应用并使用 Credential Manager，除了上述后端配置外，还需要：

- 在 RP 域名的 `/.well-known/assetlinks.json` 中放置数字资产链接文件，建立应用与网站之间的信任关系。
- 在 Android 代码中构建 `CreatePublicKeyCredentialRequest` 时，传入的 RP ID 必须与后端一致，且与 assetlinks 中声明的网站匹配。

---

## 6. 常见问题

| 现象 | 处理 |
|------|------|
| `userID` 报错 | 确保使用本目录下最新 `server.js`，已使用 `Uint8Array` 形式的 userID。 |
| `options.challenge` 为 undefined | 确保对 `generateRegistrationOptions` / `generateAuthenticationOptions` 使用 `await`。 |
| 注册后验证报错 Buffer undefined | 确保从 `verification.registrationInfo.credential` 取 `publicKey`、`id`、`counter`。 |

---

此示例完整展示了 WebAuthn 的核心流程，你可以在此基础上扩展用户管理、数据库存储等实际需求。
