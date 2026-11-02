# MuYu Camera Workbench

个人局域网摄像头研究与管理项目：把两台 RTSP 摄像头整合到带 TOTP 登录的 Web 管理台，在 Linux 服务器上持续录像。

本仓库发布脱敏的应用源码、离线测试和部分自研嵌入式组件。原厂固件、Flash 镜像、设备密钥、生产配置、录像、截图和私有实验记录不在仓库中。

## 功能

- 摄像头一／摄像头二切换；两台后台分别持续录像。
- 固定 ID、MAC、ONVIF UUID 绑定，支持手动 IP；摄像头一额外校验 SSH 主机密钥。
- 浏览器有声实时预览、有声回放、时间轴跳转、边播放边转换及原始 MKV 下载。
- 两台共用十进制 32 GB 预算，10 分钟按关键帧分段，自动清理最旧已完成片段。
- 摄像头一支持连续云台摇杆、失联停止、Wi-Fi 测试回退及受限的 SSH 媒体恢复。
- 摄像头二提供视频、声音、录像；含部分旧固件的 RTSP/RTCP 保活兼容层。
- 单管理员 RFC 6238 TOTP；加密密钥、持久 Session、防重放、限速、CSRF、本地恢复。
- 有效操作后 Session 滑动续期 48 小时，默认最长 30 天；视频与轮询不续期。
- 手机布局与 HTTPS 反向代理接入。

## 适用设备

当前业务适配两种实际设备，并非通用 ONVIF NVR：

| 槽位 | 适配对象 | 取流及管理 |
| --- | --- | --- |
| `cam1` | TL-IPC42A-4 定制版，SSC325 / SC2231 / 8 MiB NOR | H.265 1080P 约 14–15 fps；定制 SSH、ubus 电机、Wi-Fi 接口 |
| `cam2` | TL-IPC40A-Focus 旧固件 | H.264 720P、G.711、RTSP `/stream1`，仅视频与录像 |

云台、Wi-Fi、自动重启恢复依赖摄像头一定制运行环境，普通设备不能直接套用。示例中的 IP、MAC、UUID 和凭据必须换为自己的配置。

早期研究确认 SSC325 / 8 MiB 定制版与 Realtek / 16 MiB 零售版硬件不同，不能互刷。仓库不提供通用刷机包或一键刷写命令。

## 快速开始

服务器使用 Linux，建议 Python 3.13 或更新版本，需 `ffmpeg`、`ffprobe`、`iproute2`。浏览器预览由服务器转换为 H.264/AAC。

```sh
sudo apt-get update
sudo apt-get install python3-venv ffmpeg iproute2
python3 -m venv .venv
.venv/bin/pip install -r server/requirements.txt
export CAM_DATA="$PWD/data"
export CAM_LAN_CIDR="192.168.1.0/24"
export CAM_SERVER_IP="192.168.1.2"
export CAM_BIND_HOST="127.0.0.1"
export CAM_PORT="8080"
umask 077
mkdir -p "$CAM_DATA"
cp server/config.example.json "$CAM_DATA/config-input.json"
```

编辑私有的 `config-input.json`：填入自己的设备 IP、MAC、UUID、摄像头一 SSH 密码及独立核验过的 `ssh-ed25519` 主机公钥。随后执行：

```sh
.venv/bin/python server/camera_web.py --init < "$CAM_DATA/config-input.json"
rm "$CAM_DATA/config-input.json"
.venv/bin/python server/camera_web.py --totp-init
.venv/bin/python server/camera_web.py
```

在站点打开 `/bind#token=初始化命令输出的授权`，用 Aegis、Google Authenticator 或 2FAS 扫码并确认，然后用 6 位验证码登录。CLI 和服务必须使用相同的 `CAM_DATA`。本机可访问 `http://127.0.0.1:8080`；其他机器访问请配置监听地址或 HTTPS 代理。

- [部署、配置和 API](server/README.md)
- [TOTP 恢复与加密备份迁移](docs/auth-recovery.md)
- [嵌入式源码和编译](embedded/README.md)
- [发布范围与验证记录](docs/public-release.md)

## 测试

离线测试使用临时目录、模拟时钟与协议样本，不连接真实设备。文件锁相关测试在 Linux/WSL 执行。

```sh
.venv/bin/pip install -r server/requirements-dev.txt
.venv/bin/python -m pytest server -q
.venv/bin/python server/camera_web.py --self-test
node tools/test_camera_selector.cjs
```

TF 卡本地录像、视觉识别、多管理员及任意数量设备尚未实现。媒体恢复用于缓解故障与采集现场，未声称根治厂商媒体程序崩溃。新设备与新代理环境仍需实机验收。

仓库目前未附加开源许可证；公开可见不代表授予额外的再分发或使用许可。依赖库与外部工具适用各自许可证。
