# 部署与配置

`camera_web.py` 内含页面、CSS、JavaScript 与 API。同目录需要 `totp_auth.py`、`media_guard.py`、`multi_camera.py`、`rtsp_compat.py`。使用单进程 uvicorn，内部线程独立管理两台设备及共享存储。

## 私有配置

复制 `config.example.json` 到私有位置并填写实际值，通过 `camera_web.py --init` 标准输入导入；已有配置拒绝覆盖。示例身份与凭据均为占位值，不要提交填写后的配置。

| 路径，相对于 `CAM_DATA` | 内容 |
| --- | --- |
| `config.json` | 摄像头凭据、绑定身份、录像开关、Wi-Fi 派生配置、容量预算 |
| `recordings/cam1`、`cam2` | 原始录像 |
| `playback-cache/cam1`、`cam2` | 有声回放缓存 |
| `auth.*` | 密钥、认证状态、持久 Session、限速、防重放 |
| `media-incidents` | 摄像头一故障现场，可能含敏感内存 |

数据目录权限 0700，配置及认证文件权限 0600。必须使用持久磁盘。旧配置仍可迁移，第二台真实身份须通过 `CAM2_EXPECTED_MAC`、`CAM2_EXPECTED_UUID`、`CAM2_CAMERA_IP` 预先设置。

`cam1` 的云台、Wi-Fi、SSH 恢复依赖定制摄像头；`cam2` 只开放视频、声音、录像。取流路径 `/stream1`、RTSP 554；摄像头一 SSH 为 root / 2222，主机公钥须独立核验。此版本没有任意设备能力编辑器。

## 环境变量

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `CAM_DATA` | `/var/lib/cam-manager` | 持久私有数据目录 |
| `CAM_BIND_HOST` | `CAM_SERVER_IP`，未设置时 `127.0.0.1` | HTTP 监听 |
| `CAM_PORT` | `80`，systemd 示例为 `8080` | HTTP 端口 |
| `CAM_SERVER_IP` | `127.0.0.1` | 服务器备用 IP，也从设备目标中排除 |
| `CAM_PUBLIC_HOST` | `localhost` | 显示的管理域名，可附端口 |
| `CAM_LAN_CIDR` | `192.168.1.0/24` | 允许的设备网段 |
| `CAM_DISCOVERY_BIND` | `0.0.0.0` | UDP 发现绑定地址 |
| `CAM_TRUSTED_PROXIES` | `127.0.0.1,::1` | 有权设置转发来源/协议头的代理 IP |
| `CAM_ALLOWED_ORIGINS` | 空 | 必要时额外允许的完整同源地址，逗号分隔 |
| `CAM_SESSION_TTL` | `172800` | 有效操作后的滑动会话期限，秒 |
| `CAM_SESSION_ABSOLUTE_TTL` | `2592000` | 绝对期限，秒；`0` 表示关闭 |
| `CAM_DISK_FREE_BYTES` | `2147483648` | 文件系统可用空间底线，默认 2 GiB，最小 256 MiB |
| `CAM_MEDIA_STALL_SECONDS` | `90` | 停流阈值，最小 60 秒 |
| `CAM_MEDIA_RECOVERY_COOLDOWN` | `1800` | 恢复冷却，最小 900 秒 |
| `CAM_MEDIA_RECOVERY_DAILY_LIMIT` | `3` | 24 小时最多恢复次数 |

建议 IPv4 `/24` 网络。回退扫描最多检查网段前 254 个主机，大网段请用 ONVIF 发现或手动 IP。手动指定 IP 仍须通过绑定身份检查。

## systemd 新安装

已有生产环境先备份，不要覆盖数据。全新安装示例：

```sh
sudo useradd --system --home /var/lib/cam-manager --shell /usr/sbin/nologin cam-manager
sudo install -d -o cam-manager -g cam-manager -m 0700 /var/lib/cam-manager
sudo install -d /opt/cam-manager /etc/cam-manager
sudo install -m 0644 server/camera_web.py server/totp_auth.py server/media_guard.py server/multi_camera.py server/rtsp_compat.py server/requirements.txt /opt/cam-manager/
sudo python3 -m venv /opt/cam-manager/venv
sudo /opt/cam-manager/venv/bin/pip install -r /opt/cam-manager/requirements.txt
sudo install -m 0600 server/environment.example /etc/cam-manager/environment
sudoedit /etc/cam-manager/environment
sudo install -m 0644 server/cam-manager.service /etc/systemd/system/cam-manager.service
```

启动前以服务用户导入私有配置并生成 TOTP 授权。CLI 不会自动加载 systemd 环境文件，须显式传入相同的环境参数，尤其 `CAM_DATA` 与 `CAM_LAN_CIDR`：

```sh
sudo -u cam-manager env CAM_DATA=/var/lib/cam-manager CAM_LAN_CIDR=192.168.1.0/24 \
  /opt/cam-manager/venv/bin/python /opt/cam-manager/camera_web.py --init < /secure/path/config-input.json
sudo -u cam-manager env CAM_DATA=/var/lib/cam-manager \
  /opt/cam-manager/venv/bin/python /opt/cam-manager/camera_web.py --totp-init
sudo systemctl daemon-reload
sudo systemctl enable --now cam-manager
```

默认站点 `http://127.0.0.1:8080`。远程访问请配置 HTTPS 代理，或仅在可信局域网改变 `CAM_BIND_HOST`。日志：`journalctl -u cam-manager -n 60`。

## HTTPS 反向代理

使用独立域名根路径，保留 Host，关闭视频缓冲及缓存。公网登录必须 HTTPS。将代理真实 IP 加入可信代理列表，不要信任任意来源的转发头。

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 3600s;
    gzip off;
}
```

以上 location 放进有效证书的 HTTPS server。HTTPS 登录使用 `Secure`、`HttpOnly`、`SameSite=Strict` Cookie；本地 HTTP 维护允许非 Secure Cookie。不要直接公网映射应用 HTTP 端口。

## API 与运行行为

登录、退出、TOTP、`/api/cameras` 为全局接口。其他设备接口必须含且只含一个 `?camera_id=cam1` 或 `?camera_id=cam2`：状态、录像、PTZ、Wi-Fi、发现、IP 配置、实时流、回放、下载。缺失/重复 ID 返回 400，未知 ID 返回 404；未登录先返回 401，未开放能力返回 409。

后端验证 Session，修改操作还验证同源及 CSRF；流式响应周期检查会话撤销/到期。有效操作成功后续期 48 小时，轮询、视频、下载不续期。选择设备只影响当前标签页。

录像按 600 秒在关键帧附近切分，断线或暂停可能产生短片段。32 GB 为两台共用的十进制预算，含录像及缓存，活动片段与使用中文件受保护。每台共享预览编码器；回放最多两路，后台完整转换最多一路。

除总配额外，还检查录像所在文件系统的实际可用空间。低于默认 2 GiB 时，先清理可删除的回放缓存，再按时间清理本项目最旧已完成录像，目标恢复至底线以上约 256 MiB。不会删除活动片段、正在使用的文件或其他应用的数据；无法释放足够空间时暂停录像和缓存转换。即使录像未达到 32 GB，也可能因其他程序占满磁盘触发该保护。认证存储故障返回带说明和重试时间的 503，并拒绝受保护操作，不绕过认证。

Wi-Fi 配置保存在服务器、设备 RAM 生效，断电后须先用固件默认网络或网线联系服务器才能重下发，不写摄像头 Flash。SSH 恢复只作用于已验证的摄像头一，单纯断网不触发设备重启。
