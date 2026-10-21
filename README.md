# dvripkit

[![CI](https://github.com/open0x01/dvripkit/actions/workflows/ci.yml/badge.svg)](https://github.com/open0x01/dvripkit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/open0x01/dvripkit?sort=semver)](https://github.com/open0x01/dvripkit/releases/latest)

纯 Go 实现的大华（Dahua）DVRIP 登录校验器。不加载 NetSDK、不依赖任何 `.so`/`.dll` 资产，报文与摘要算法全部在 Go 里完成。

DVRIP 二进制握手流程的组包、字节序、哈希公式，均已在 8 组独立抓包（含真机）上逐字节复现，因此纯 Go 客户端发出的字节与 `libdhnetsdk` 完全一致。

> **仅限授权使用。** 请只在你自己拥有或已获得书面授权的设备/网络上使用。未经授权对他人设备进行登录尝试在多数司法辖区属于违法行为。

---

## 功能

- DVRIP 二进制登录握手（TCP 37777），单次凭据校验
- 设备级连续连接失败计数，避免一次网络抖动把整台设备误判为不可达
- 登录结果三态划分：成功 / 普通失败 / 账号锁定（附剩余锁定秒数）
- 可离线自测：内置假设备，不需要任何真实目标

## 目录结构

```
.
├── main.go                     # CLI 入口 + DVRIP 实现（协议、哈希、错误码分类、设备状态）
├── pure_test.go                # 离线测试（含真机抓包的哈希 ground truth）
├── go.mod
├── .github/workflows/
│   ├── ci.yml                  # 每次 push/PR：vet + test + 四平台交叉编译冒烟
│   └── release.yml             # 打 v* tag：构建四平台产物并发布到 Release
├── .gitattributes
└── .gitignore
```

## 下载

预编译二进制在 [Releases](https://github.com/open0x01/dvripkit/releases/latest) 页面，覆盖：

| 平台 | 架构 | 文件 |
| --- | --- | --- |
| Windows | amd64 | `dvripkit_<version>_windows_amd64.zip` |
| Windows | arm64 | `dvripkit_<version>_windows_arm64.zip` |
| Linux | amd64 | `dvripkit_<version>_linux_amd64.tar.gz` |
| Linux | arm64 | `dvripkit_<version>_linux_arm64.tar.gz` |

每个压缩包内含可执行文件与 `README.md`；同批资产附带 `checksums.txt`（SHA-256），可用 `sha256sum -c checksums.txt --ignore-missing` 校验。

## 构建

需要 Go 1.25 或更高版本。

```bash
go build -o dvripkit .
```

带版本号构建（与 Release 产物一致）：

```bash
go build -trimpath -ldflags "-s -w -X main.version=v0.1.0" -o dvripkit .
```

## 用法

```bash
./dvripkit -target 192.168.1.108:37777 -user admin -pass admin123
```

查看版本：

```bash
./dvripkit -version
```

参数也可通过环境变量提供（便于脚本化）：

| 参数 | 环境变量 | 说明 |
| --- | --- | --- |
| `-target` | `DAHUA_DVRIP_TARGET` | 目标 `host` 或 `host:port`，端口缺省 37777 |
| `-user` | `DAHUA_DVRIP_USER` | 用户名 |
| `-pass` | `DAHUA_DVRIP_PASS` | 密码 |
| `-timeout` | — | 单次连接超时（秒），缺省 5 |

输出示例：

```
==> DVRIP 二进制流程 192.168.1.108:37777 user=admin
结果: 认证成功
```

其它可能的结果：

- `结果: 认证失败(口令错或用户不存在)`
- `结果: 账号锁定/禁止登录 (设备账号锁定/禁止登录(nError=104)(剩余235秒))`
- `结果: 设备不可达(连续连接失败达阈值)`

## 测试

```bash
go test -v .
```

全部用例都是离线的（本地起一个假设备监听 `127.0.0.1`），不会连接任何真实目标。

测试覆盖：

- `dahuaGen1Hash` / `dvripLoginHash` 的单元校验
- 8 组 NetSDK 实际登录体的逐字节 ground truth（覆盖 3 个口令、3 个 realm、6 个 random，含真机抓包）
- realm 解析必须保留 `Login to ` 前缀
- 成功 / 口令错 / 锁定 / 瞬态错误 / 不可达 各分支
- 锁定与瞬态错误不计入「不可达」阈值的语义

## 协议要点

### 握手流程

1. 发送 A0 05 challenge 请求（32 字节头，空 body）；
2. 设备回文本 body，含 `Realm:` 与 `Random:` 两行；
3. 用用户名、密码、realm、random 推导登录摘要；
4. 发送 A0 05 登录请求，读取响应头中的错误码。

### 报文头（32 字节）

| 偏移 | 长度 | 含义 |
| --- | --- | --- |
| 0–3 | 4 | 命令字，**大端**。challenge 与登录同为 `0xa0050060` |
| 4–7 | 4 | body 长度，**小端** |
| 8–23 | 16 | 会话随机区。challenge 填随机字节，登录填 0 |
| 24–31 | 8 | magic，**大端**。challenge `0x040200010000a1aa`，登录 `0x040200080000a1aa` |

响应头以 `b0 00` 或 `b0 01` 开头；错误码位于响应头 offset 8–9（大端），`0x0008` 为成功。

### 登录摘要

```
HA1 = UPPER(MD5(user + ":" + realm + ":" + password))
H1  = UPPER(MD5(user + ":" + random + ":" + HA1))
H2  = UPPER(MD5(user + ":" + random + ":" + gen1(password)))
body = user + "&&" + H1 + H2
```

`realm` 必须是设备 challenge 的**原文**，包含 `Login to ` 前缀——剥掉前缀会导致 HA1 与设备期望值不一致，登录必然失败。

`gen1` 是大华 8 位老摘要：对密码取 MD5，每两个相邻字节求和后对 62 取模，映射到 `[0-9A-Za-z]`。

### 错误码

响应码形如 `0x01XX`，低字节是相对 NetSDK `lastErr` 码 100 的偏移：

| 响应码 | NetSDK 码 | 含义 | 处理 |
| --- | --- | --- | --- |
| `0x0100` | 100 | 口令错 | 普通失败 |
| `0x0101` | 101 | 用户不存在 | 普通失败 |
| `0x0104` | 104 | 账号锁定 | 停止该设备 |
| `0x0105` | 105 | 黑名单 | 停止该设备 |
| `0x0107` | 107 | 连接超时 | 计入连接失败 |
| `0x0108` | 108 | 网络连接失败 | 计入连接失败 |
| `0x010A` | 110 | 连接数超限 | 计入连接失败 |
| `0x010D` | 113 | IP 无权限 | 停止该设备 |
| `0x0112` | 118 | 未初始化 | 停止该设备 |

### 不可达判定

传输层失败（拨号/读写）按 `ip:port` 归集计数，**连续** 3 次才判定为不可达；只要设备有一次正常响应就清零。协议层失败（口令错、锁定）不计入。

`ClearDeviceState()` 用于在任务之间清空计数缓存。

## 已知限制

- 只实现 DVRIP 二进制登录流程；JSON（`F6`）登录接口不在范围内
- 未适配新固件的「先建会话（`/RPC2_Login` 或 A0 05 带 `sessionID`）再登录」流程；目标设备若只接受该流程，会表现为认证失败
- 一次 `Scan` 只校验一组凭据，不负责字典调度
- 未处理设备主动推送的保活/心跳报文

## 发布

打 tag 即触发发布（workflow 会自动构建四平台产物并挂到 Release）：

```bash
git tag v0.1.0
git push origin v0.1.0
```

产物命名遵循 `dvripkit_<version>_<os>_<arch>`，`version` 去掉 `v` 前缀。发布前 CI 会先跑一遍全部测试；测试不过则不会产出 Release。

## 许可

未指定。
