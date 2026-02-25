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
// 键：用户ID，值：用户对象（包含当前挑战和已注册凭证）
const users = {};

// 依赖方信息 - 必须与前端访问的域名一致
const rpID = 'localhost';      // 如果使用 IP 访问，则需设置为该 IP
const expectedOrigin = 'http://localhost:3000';  // 前端完整源

// 模拟用户数据库（实际应从数据库获取）
function findUser(userHandle) {
  return users[userHandle];
}
function saveUser(user) {
  users[user.id] = user;
}

// 将用户名转为 WebAuthn 要求的 userID（Uint8Array，最多 64 字节）
function toWebAuthnUserID(username) {
  const hash = crypto.createHash('sha256').update(username, 'utf8').digest();
  return new Uint8Array(hash);
}

// ---------- 1. 注册：生成注册选项 ----------
app.post('/generate-registration-options', async (req, res) => {
  const { username } = req.body;

  // 内部用字符串做用户键；generateRegistrationOptions 需要 Uint8Array
  const userHandle = `user_${username}`;
  const userID = toWebAuthnUserID(username);

  // 生成注册选项（异步，需 await）
  const options = await generateRegistrationOptions({
    rpID,
    rpName: 'Example App',
    userID,
    userName: username,
    // 不要求 attestation 语句
    attestationType: 'none',
    // 指定支持的算法（推荐使用 -7 = ES256）
    supportedAlgorithmIDs: [-7, -257],
  });

  // 保存挑战，以便后续验证
  const user = findUser(userHandle) || { id: userHandle, username, devices: [] };
  user.currentChallenge = options.challenge;
  saveUser(user);

  res.json(options);
});

// ---------- 2. 注册：验证认证器响应 ----------
app.post('/verify-registration', async (req, res) => {
  const { username, attestationResponse } = req.body;
  const userID = `user_${username}`;
  const user = findUser(userID);
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: user.currentChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      // 保存凭证信息到用户设备列表（新版 API 使用 registrationInfo.credential）
      const { credential } = verification.registrationInfo;
      user.devices.push({
        credentialPublicKey: Buffer.from(credential.publicKey).toString('base64'),
        credentialID: credential.id, // base64url 字符串
        counter: credential.counter,
      });
      // 清除挑战
      delete user.currentChallenge;
      saveUser(user);
      return res.json({ verified: true });
    } else {
      return res.status(400).json({ verified: false, error: 'Verification failed' });
    }
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error: error.message });
  }
});

// ---------- 3. 登录：生成认证选项 ----------
app.post('/generate-authentication-options', async (req, res) => {
  const { username } = req.body;
  const userID = `user_${username}`;
  const user = findUser(userID);
  if (!user || user.devices.length === 0) {
    return res.status(400).json({ error: 'User not registered or no devices' });
  }

  // 提取该用户的所有已注册凭证ID（id 为 base64url 字符串）
  const allowCredentials = user.devices.map(dev => ({
    id: dev.credentialID,
    type: 'public-key',
  }));

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: 'preferred',
  });

  // 保存挑战
  user.currentChallenge = options.challenge;
  saveUser(user);

  res.json(options);
});

// ---------- 4. 登录：验证认证器断言 ----------
app.post('/verify-authentication', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const userID = `user_${username}`;
  const user = findUser(userID);
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  // 从用户设备列表中找到本次使用的凭证（id 为 base64url）
  const device = user.devices.find(dev => dev.credentialID === assertionResponse.id);
  if (!device) {
    return res.status(400).json({ error: 'Credential not found' });
  }

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
      // 更新计数器
      device.counter = verification.authenticationInfo.newCounter;
      delete user.currentChallenge;
      saveUser(user);
      return res.json({ verified: true });
    } else {
      return res.status(400).json({ verified: false, error: 'Authentication failed' });
    }
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error: error.message });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});