# WorkBuddy 账号管理台

Windows 本地工作台：管理本人 WorkBuddy 账号、查询官方当前积分、短信验证添加账号、切换登录身份和管理本地对话。

## 下载直接运行

1. 安装 Windows 版 WorkBuddy，并打开客户端。已有账号可先在客户端登录。
2. 从 [最新版本](https://github.com/jscjscjscjscjsc/workbuddy-account-hub/releases/latest) 下载 `WorkBuddyAccountHub-v1.0.0-windows-x64.zip`。
3. **完整解压**到可写目录，再双击 `WorkBuddyAccountHub.exe` 或 `一键启动.cmd`。Windows 可运行包自带 Python 运行时，无需另装 Python 或 Node。
4. 浏览器自动打开本地管理台。默认地址为 `http://127.0.0.1:8770/`；端口占用时自动寻找空闲端口并打开实际地址。

请保留解压目录中的全部文件。此版本仅支持 Windows x64；程序不需要管理员权限。源码 ZIP 需要 Python，可运行 ZIP 不需要。

## 使用

- **账号收录**：打开 WorkBuddy 并登录后，管理台自动收录当前账号。保险库不会预装任何账号。
- **添加手机号**：点击添加手机号，发送验证码，再验证添加。页面立即显示发送状态；官方确认发送成功后开始 60 秒倒计时。后台不会自动重复发短信，实际送达时间由官方服务决定。
- **积分**：读取客户端同款官方当前周期汇总，按账号凭据核对身份；历史容量不参与余额求和。缓存一分钟，点击查积分可强制刷新。令牌失效时显示错误，不显示其他账号余额。
- **切换账号**：有有效认证且客户端支持身份热加载时可保持 WorkBuddy 打开切换。有正在输出的任务时会阻止切换；只有客户端确认身份后才报告成功。完整登录态切换需要先退出 WorkBuddy。
- **本地对话共享、状态矫正、签到**：可在界面手动操作。首次运行默认关闭自动共享、自动状态矫正和自动签到，按需开启；自动收录默认开启。
- **停止管理台**：点击页面中的停止按钮。关闭浏览器不会停止后台；停止管理台不会关闭 WorkBuddy。

## 数据与兼容性

账号快照、设备密钥缓存、设置保存在程序目录的 `保险库/`，后台日志保存在 `运行日志/`。这些目录含敏感登录资料，只应留在自己的电脑，**不要上传或分享整个使用过的程序目录**。发布 ZIP 和 Git 仓库均不包含这些数据。

网页和管理 API 只监听本机回环地址。账号查询、短信验证和签到需要连接 WorkBuddy 官方服务。本项目是第三方本地工具，使用客户端内部接口；WorkBuddy 更新后可能需要适配。切换认证与资源接口已在本机安装版本验证，短信发送由用户反馈成功；尚未在所有客户端版本和全新设备上验证。

非默认安装位置：先打开 WorkBuddy，工具会从运行进程自动定位；也可设置 `WBH_APP_EXE` 为完整 exe 路径。短信请求默认直连，确需系统代理时设置 `WBH_LOGIN_USE_PROXY=1`。

## 从源码运行

需要 Windows 和 Python 3.10+，运行依赖仅 Python 标准库。可双击 `一键启动.cmd`（优先使用 WorkBuddy 自带 Python），或执行：

```powershell
python -X utf8 launch.py
```

## 验证与构建

隔离回归不会使用真实手机号发送短信，也不会修改真实账号快照：

```powershell
python -X utf8 验证脚本/稳定性回归.py
python -X utf8 验证脚本/验证码积分回归.py
python -X utf8 验证脚本/后台启动验收.py
```

构建 Windows 可运行目录：

```powershell
python -m pip install -r requirements-build.txt
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
```

输出为 `dist/WorkBuddyAccountHub/`。发布时完整打包该目录，并检查不含保险库、日志、数据库或真实手机号。

本项目采用 MIT License；WorkBuddy 商标及客户端归其各自权利人所有。
