/*
 * wbkey.js —— 从 WorkBuddy 自带的原生绑定里取出"本机 at-rest 主密钥"。
 *
 * 原理
 * ----
 * WorkBuddy 桌面端把登录会话（accessToken / refreshToken / 手机号）写在
 *   <用户目录>\Local Settings\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info
 * 里面的敏感字段用 "$wbEncrypted 信封" 包起来：
 *   {"suite":1,"keyId":"<16位hex>","nonce":b64,"authTag":b64,"ciphertext":b64}
 * 密钥由 Windows 侧的原生模块 electron_browser_workbuddy_storage 保管，
 * 该模块被编译进 WorkBuddy.exe，并通过 Node 的 linked binding 暴露：
 *   loggerGet() -> 形如 {"version":1,"atRestSecretKey":"<44字符base64>", ...}
 *
 * 我们以 ELECTRON_RUN_AS_NODE=1 的方式启动 WorkBuddy.exe 跑这个脚本，
 * 就能在不启动界面、不影响正在运行的 App 的前提下，拿到那个主密钥。
 * 拿到之后在 Python 侧用 bcrypt(AES-256-GCM) 自行解密，无需再依赖 App。
 *
 * 输出：单行 JSON —— {"ok":true,"secret":"<44字符base64>"} 或 {"ok":false,"reason":"..."}
 * 除这一行外不产生任何其它输出。
 */
'use strict';

function emit(obj) {
  process.stdout.write(JSON.stringify(obj));
  process.exit(0);
}

var binding;
try {
  binding = process._linkedBinding('electron_browser_workbuddy_storage');
} catch (e) {
  emit({ ok: false, reason: 'native-binding-unavailable: ' + (e && e.message ? e.message : String(e)) });
}

var payload;
try {
  payload = binding.loggerGet();
} catch (e) {
  emit({ ok: false, reason: 'loggerGet-failed: ' + (e && e.message ? e.message : String(e)) });
}

if (typeof payload !== 'string' || payload.length === 0) {
  emit({ ok: false, reason: 'empty-payload' });
}

var obj;
try {
  obj = JSON.parse(payload);
} catch (e) {
  emit({ ok: false, reason: 'payload-not-json' });
}

var secret = obj && obj.atRestSecretKey;
if (typeof secret !== 'string' || secret.length !== 44) {
  emit({ ok: false, reason: 'bad-atRestSecretKey' });
}

emit({ ok: true, version: obj.version, secret: secret });
