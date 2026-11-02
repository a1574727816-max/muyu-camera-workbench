# TOTP 恢复与备份

RFC 6238：SHA-1、6 位、30 秒、至少 160 bit Base32 随机密钥，容差前后各一个时间窗口。兼容 Aegis、Google Authenticator、2FAS，不调用第三方服务；离线时仍须保证手机与服务器时间准确。

CLI 与服务必须使用相同 `CAM_DATA`。

## 首次绑定

```sh
sudo -u cam-manager env CAM_DATA=/var/lib/cam-manager \
  /opt/cam-manager/venv/bin/python /opt/cam-manager/camera_web.py --totp-init
```

打开站点的 `/bind#token=输出的授权`，扫码后输入验证码确认。授权限时、一次有效；二维码和手动密钥只在授权绑定过程中返回，不应复制到日志或 Git。公共访客不能生成初始化或恢复授权。

## 会话与换机

Session ID 为安全随机数，服务器保存哈希。有效业务操作成功后续期 48 小时，视频及轮询不续期；绝对期限默认 30 天。退出立即撤销，重启保留未过期会话。限速、防重放均持久化；同一 TOTP 时间步不可重复登录。

正常换手机：登录后点击“更换验证器”，输入旧验证码、扫描新二维码、输入新验证码确认。确认前旧密钥仍有效；成功后旧密钥失效并撤销既有会话。

丢失手机只能由服务器管理员本地恢复：

```sh
sudo env CAM_DATA=/var/lib/cam-manager \
  /opt/cam-manager/venv/bin/python /opt/cam-manager/camera_web.py --totp-recover
sudo chown -R cam-manager:cam-manager /var/lib/cam-manager
```

恢复撤销旧认证与会话，生成新绑定授权，不删除录像或摄像头配置。注意恢复后文件应归服务用户所有。

## 加密备份与迁移

备份包含恢复 TOTP 所需的密钥和认证状态，外层由口令加密；不包含设备配置、录像或已有 Session。口令从标准输入传递，用交互输入避免写入 shell 历史：

```sh
read -r -s -p '备份口令: ' backup_passphrase; printf '\n'
printf '%s\n' "$backup_passphrase" | sudo -u cam-manager env CAM_DATA=/var/lib/cam-manager \
  /opt/cam-manager/venv/bin/python /opt/cam-manager/camera_web.py --totp-backup /var/lib/cam-manager/totp.backup
unset backup_passphrase
```

备份复制到私有介质、口令另存。新服务器安装同版本程序并建立私有数据目录后：

```sh
read -r -s -p '备份口令: ' backup_passphrase; printf '\n'
printf '%s\n' "$backup_passphrase" | sudo -u cam-manager env CAM_DATA=/var/lib/cam-manager \
  /opt/cam-manager/venv/bin/python /opt/cam-manager/camera_web.py --totp-restore /secure/path/totp.backup
unset backup_passphrase
```

默认拒绝覆盖已有认证；确需覆盖时加 `--force`，先停止服务，恢复后重新启动，用原验证器的新时间步登录。恢复不依赖固定 IP 或旧目录。设备配置与录像须独立加密备份，认证恢复不覆盖它们。恢复验证测试见 `server/test_totp_auth.py`。
