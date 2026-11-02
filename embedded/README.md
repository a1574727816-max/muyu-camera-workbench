# 自研嵌入式组件

源自 SSC325 / SC2231 / 8 MiB NOR 摄像头研究，供审阅与移植，不是完整固件。原厂内核、驱动、RootFS、密钥、传感器初始化表及 Flash 拼装/刷写脚本不在发布范围。

| 路径 | 作用 |
| --- | --- |
| `netguard/netguard.c` | 管道日志、两份各 64 KiB 轮转、解除子进程文件大小限制、flock 与陈旧 PID 启动时间核验 |
| `onvif-ptz/bridge.c` | ONVIF PTZ SOAP 到本机 ubus 电机控制，Digest 认证与独立停止守护 |
| `onvif-ptz/md5.c`、`md5.h` | 旧设备 HTTP Digest 互操作，不用于 Web TOTP 或口令存储 |
| `rtsp-warmup/warm-rtsp.c` | 有超时和数据量上限的回环 RTSP 预热 |
| `ram-reader/ram_reader_arm.S` | 特定 Bootloader 地址映射下的只读 RAM/CRC 实验 |
| `ram-reader/loop-ro.c` | 将固定 RAM 镜像挂接只读 loop 设备 |

Linux 主机编译检查：

```sh
sudo apt-get install build-essential libexpat1-dev
mkdir -p build
cc -O2 -std=c11 -Wall -Wextra -Werror embedded/netguard/netguard.c -o build/netguard
cc -D_GNU_SOURCE -O2 -std=c11 -Wall -Wextra -Werror \
  embedded/onvif-ptz/bridge.c embedded/onvif-ptz/md5.c -lexpat -lm -o build/onvif-ptz-bridge
cc -O2 -std=c11 -Wall -Wextra -Werror -c embedded/rtsp-warmup/warm-rtsp.c -o build/warm-rtsp.o
cc -O2 -std=c11 -Wall -Wextra -Werror embedded/ram-reader/loop-ro.c -o build/loop-ro
python3 tools/test_netguard_host.py --binary build/netguard --output build/netguard-test.json
```

设备版本需要匹配的 ARMv7 hard-float 交叉工具链及依赖，不能使用主机 ELF。PTZ 依赖特定 ubus 方法及私有 Digest 授权文件；监听和后端默认回环，运行时由命令行明确配置。RAM 汇编依赖特定硬件，不能直接用于其他设备。主机编译通过不代表实机兼容。
