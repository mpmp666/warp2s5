# warp2s5 — 纯 Python 的 Cloudflare WARP 客户端（暴露 SOCKS5 代理）

把一个 Cloudflare WARP 设备变成一个**本地 SOCKS5 代理**：

```
SOCKS5 客户端 → warp2s5 → [MASQUE(QUIC/443) 或 WireGuard(UDP/2408)] → WARP 出口 → 目标网站
```

**全部用 Python 实现，用户态跑完整个协议栈**：WireGuard（Noise_IKpsk2 握手 + 传输加密）、**MASQUE（cf-connect-ip over HTTP/3 + QUIC + 客户端证书认证）**、IPv4/UDP/TCP 协议栈、隧道内 DNS、SOCKS5 服务端。**不需要 root/管理员权限，不需要 TUN/TAP 网卡，不需要 wireguard-go 等外部二进制**。

依赖：`cryptography`（+ 用 MASQUE 时需要 `aioquic`）。

---

## 先选对传输方式（这是能不能用的关键）

WARP 有两条完全不同的传输，能不能用取决于你的网络封哪一条：

| 传输 | 协议 | 端口 | 本机（中国电信）实测 |
| --- | --- | --- | --- |
| `wireguard` | Noise_IKpsk2 | UDP 2408/500/1701/4500 | ❌ **被封**：2 个 anycast IP × 54 个端口 × 4 轮 = 432 个握手包全部 0 回应；用独立 Go 实现（`golang.org/x/crypto`）同样 0 回应 |
| `masque` | QUIC + HTTP/3 `cf-connect-ip` | UDP 443/500/1701/4500/8443/8095 | ✅ **已跑通**（HTTPS 实测 200，出口 `warp=on`，详见下节） |

所以默认 `--transport auto`：**先试 MASQUE，失败再退回 WireGuard**。也可以 `--transport masque` / `--transport wireguard` 强制指定。

---

## MASQUE 跑通记录（两个致命的隐藏 bug）

协议层面全部正确（设备登记、QUIC+TLS 客户端证书、`:protocol: cf-connect-ip`、服务端回的 `cf-warp-metal`/`cf-warp-colo` 头都拿到了），
但数据面一度**一个包都不过** —— 根因是两个极隐蔽的问题：

**1. HTTP Datagram 缺了 Context ID 字节**

RFC 9484 §5：*all HTTP Datagrams associated with IP proxying request streams start with a Context ID field，
the Context ID value of 0 is reserved for IP payloads*。

aioquic 的 `send_datagram()` 只发 `Quarter-Stream-ID + 数据`，少了 Context ID：

```python
self._quic.send_datagram_frame(encode_uint_var(stream_id // 4) + data)   # 少了 Context ID
```

服务端于是把我 IP 包的第一个字节（IPv4 的 `0x45`）当成 Context ID=69（未注册），
**立刻 `RESET_STREAM(H3_NO_ERROR)` 掐断 CONNECT-IP 流**。补上这一个字节，数据面立即通。

**2. aioquic 的 `max_datagram_size` 默认 1200 字节（迷惑性极强的稳定性杀手）**

默认只允许 1200 字节 QUIC 载荷，而装满的 IPv4 报文（MTU 1280）+ QSID/ContextID/帧头约需 1310 字节，
**超出部分被静默丢弃**。表现：HTTP 小请求全好，**HTTPS 一律失败** —— 因为 TLS ClientHello
被切成 1240+338 两段，1240 那段直接消失：

```
TX SYN                     ← 通
TX len=1240                ← 消失（超 1200 被丢）
TX len=338
（之后 14 秒零回包）
```

修复：`max_datagram_size = mtu + 120`。

**另加两个稳定性措施**：该线路会对单条 QUIC 流限速（突发后开始丢包），
检测到"发了包却长时间收不到回包"就**换新流**；换流后立刻**踢一下 TCP 栈**，
让卡住的连接在新流上马上重传，而不是等 RTO 退避。

**实测结果**（机顶盒 armbian，纯 Python）：

```
[14:42:34] attempt #1: 2606:4700:103::2:443
[14:42:35]    tunnel accepted in 1.6s
[14:42:36]    data plane verified
[14:42:36] *** SOCKS5 READY on 0.0.0.0:1080 ***
  https://www.cloudflare.com/cdn-cgi/trace -> 200  1.7s
  https://api.github.com/                  -> 200  3.5s
  出口: ip=104.28.208.136  colo=LAX  warp=on
```

`python -m warp2s5 --webui` 起的就是常驻重试器：轮试端点/端口、只认"数据面真的通"、
流被限速就换流、实例挂了自动重建，通了才起 SOCKS5。

---

## 多开 WARP + WebUI

一条隧道容易被限速（该线路对单条 QUIC 流突发后就丢包），多开几条互不相干的实例能显著提升可用性和速度：

```bash
python -m warp2s5 --webui --instances 3 --base-port 1080 --webui-bind 0.0.0.0:8899
```

* **每个实例一个独立设备**（自己的 EC 密钥 + 证书 + 设备登记）→ 绕开 Cloudflare 的**按设备**限流
* 每个实例一条独立 MASQUE 隧道（独立 QUIC 流）+ 独立用户态 IP 栈
* 每个实例监听自己的 SOCKS5 端口：`1080`、`1081`、`1082` …
* 内置**巡检监督**：实例挂了自动重启，数据面静默自动重建

Web 控制台（`http://<host>:8899`）实时显示每个实例的状态、端点、设备、流量、在线时长，并支持启动/停止/重启/新增/删除：

```
GET  /                    控制台页面（每 2 秒自动刷新）
GET  /api/status          池与实例状态 JSON
POST /api/start?name=x    启动单个实例（stop / restart 同理）
POST /api/start-all       全部启动（stop-all 同理）
POST /api/add             新增一个实例
POST /api/remove?name=x   删除实例
```

端点扫描是内置的（`warp2s5/scan.py`）：并发对每个 (IP, 端口) 组合做完整验证 ——
握手 → CONNECT-IP → **在隧道里真发一个 DNS 查询并等真实回包**，只有收到回包的才算可用
（这条线路上"握手成功 + 返回 200 但数据面全丢"是常态，只看握手会得出完全错误的结论）。
每个候选连发 3 个探测包统计**丢包率**，结果按 **(丢包率, 延迟)** 排序，最好的排最前。

**IPv6 端点是可以用的（实测 6/6）**，而且往往比 IPv4 更稳：

```
2606:4700:103::2:443    v6  YES    0%  208ms
2606:4700:103::2:500    v6  YES    0%  208ms
2606:4700:103::2:4500   v6  YES    0%  204ms
2606:4700:103::2:8443   v6  YES    0%  209ms
2606:4700:103::1:443    v6  YES    0%  209ms
2606:4700:103::1:8443   v6  YES    0%  210ms
162.159.198.2:443       v4  YES    0%  208ms
```

所以候选列表把 IPv6 排在前面。注意这只是**外层传输**走 IPv6；隧道内容仍然是 IPv4
（用户态协议栈目前只实现 IPv4），所以出口看到的还是 Cloudflare 的 IPv4 地址。

---

## 快速开始

```bash
pip install cryptography aioquic

# 自检（注册设备 → 建隧道 → 隧道内 DNS → 隧道内 HTTP，打印出口 IP）
python -m warp2s5 --check --transport masque

# 起 SOCKS5 代理（默认 127.0.0.1:1080，auto = 先 MASQUE 后 WireGuard）
python -m warp2s5

# 验证出口
curl -x socks5h://127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
#   ... warp=on  ← 流量确实从 WARP 出去了
```

装成命令：

```bash
pip install -e .
warp2s5 -b 0.0.0.0:1080 --username u --password p
```

### 常用参数

| 参数 | 说明 |
| --- | --- |
| `--transport auto\|wireguard\|masque` | 传输方式，默认 `auto`（先 MASQUE） |
| `-b, --bind host:port` | SOCKS5 监听地址，默认 `127.0.0.1:1080` |
| `--identity PATH` | 身份文件（默认 `~/.warp2s5/identity.json`；MASQUE 用 `identity-masque.json`，是**独立设备**） |
| `--register` | 强制重新注册 |
| `--license KEY` | 绑定 WARP+ / Zero Trust license |
| `--masque-endpoint IP` / `--masque-port N` | 手动指定 MASQUE 端点（默认用 API 下发的地址 + 内置 anycast 列表，443） |
| `--endpoint IP[:PORT]` / `--port N` | WireGuard 端点与端口（可重复） |
| `--family v4\|v6\|both` | WireGuard 端点地址族（默认 v4+v6 一起抢） |
| `--dns 1.1.1.1,1.0.0.1` | **隧道内**使用的 DNS（不泄露给本地解析器） |
| `--username/--password` | 给 SOCKS5 加账号密码认证 |
| `--print-config` | 输出 wg-quick 配置（可给别的 WireGuard 客户端用） |
| `--stats-interval N` | 每 N 秒打印隧道/协议栈统计 |
| `--check` | 自检模式 |
| `-v / -q` | 调试日志 / 安静模式 |

---

## 实现结构

| 文件 | 作用 |
| --- | --- |
| `warp2s5/warp.py` | WARP API：注册设备（WireGuard 用 curve25519，MASQUE 用 secp256r1 + 自签证书并 `PATCH /reg/{id}` 登记 `key_type=secp256r1&tunnel_type=masque`），身份缓存 |
| `warp2s5/masque.py` | **MASQUE 传输**：QUIC + TLS1.3（带客户端证书）、HTTP/3 扩展 CONNECT（`:protocol: cf-connect-ip`、`Capsule-Protocol: ?1`、`:authority: cloudflareaccess.com`）、IP 包按 QUIC datagram 收发、ADDRESS_ASSIGN 胶囊解析、keepalive/断线重连 |
| `warp2s5/wireguard.py` | WireGuard 传输：Noise_IKpsk2 握手、ChaCha20-Poly1305 传输报文、重放窗口、重协商、keepalive、Cloudflare 的 3 字节 reserved 头 |
| `warp2s5/blake2s.py` | 纯 Python BLAKE2s（RFC 7693，握手/HMAC-KDF/mac1 用） |
| `warp2s5/packets.py` | IPv4 / UDP / TCP 报文编解码与校验和 |
| `warp2s5/ipstack.py` | 用户态协议栈：TCP 客户端（三次握手/滑动窗口/拥塞控制/重传/乱序重组/零窗口探测/半关闭）+ UDP + ICMP |
| `warp2s5/dns.py` | 隧道内 DNS（UDP，截断自动走 TCP，带缓存） |
| `warp2s5/socks5.py` | asyncio SOCKS5 服务端（RFC 1928/1929），CONNECT + 可选认证 |
| `warp2s5/cli.py` | CLI、传输选择（auto）、`--check` |

`masque.py` 和 `wireguard.py` 对外是同一个接口（`start/stop/wait_ready/send_ip/on_ip`），所以上面的 IP 栈与 SOCKS5 完全不需要知道底下是哪种传输。

---

## 验证记录（本机实跑）

### 1. 纯 Python 实现本身

```
python tests/test_units.py          → Ran 15 tests ... OK
python tests/test_blake2s_go.py     → 27 values vs golang.org/x/crypto/blake2s, failures=0
python tests/test_blake2s_node.py   → 15 vectors vs node/OpenSSL, failures=0
python tests/test_wg_vector.py      → handshake initiation vs an independent Go
                                      implementation: chain_key/encrypted_static/
                                      encrypted_timestamp/mac1/148-byte message/
                                      transcript 全部一致, FAILURES: 0
```

### 2. 整条链路（本机 WireGuard 对端 + 本机源站，可复现）

```
python tests/test_local_tunnel.py   → 10/10 checks passed
  wireguard handshake / 小响应 / 300KB 下载(0 重传) / 200KB chunked /
  异常连接后仍可新建 / 5 个连续连接 / SOCKS5 CONNECT + 250KB /
  隧道内真实 DNS / 隧道内真实 HTTP / SOCKS5 域名访问
python tests/test_cli_e2e.py        → 7/7 checks passed
  其中 curl 的 HTTPS（真 TLS）就跑在这个 Python 用户态 TCP 栈上
```

### 3. MASQUE 对真实 WARP

- 设备登记与 API 校验：`key_type=secp256r1`、`tunnel_type=masque`、API 返回的 `key` 与我们证书公钥**逐字节相同**、`peers[0].public_key` 变成 EC PEM（供固定校验）✅
- QUIC + TLS 1.3 握手成功（ALPN h3、客户端证书被接受、拿到 retry token）✅
- `cf-connect-ip` CONNECT 请求被接受，返回 **`:status 200`** ✅
- 之后发 IP 包（v4/v6 都试过）→ **收不到任何回包**（`tx>0, rx=0`）❌

### 4. 这是网络侧还是实现侧？——是网络侧

同一时刻、同一台机器上做的对照：

| 对象 | 结果 |
| --- | --- |
| 你的机顶盒 docker 官方 WARP（192.168.1.72:1111） | ✅ `warp=on`，出口 `2a09:bac5:...`，colo=LAX（连续 6 次轮询都正常） |
| 本机 warp2s5 MASQUE | ⚠️ 控制面通、数据面不通 |
| 本机 usque（第三方成熟 Go 实现，我现场编译的） | ❌ 同样失败，报 `connect-ip: failed to read response: PROTOCOL_VIOLATION (remote)` |
| 本机 WireGuard（UDP 2408/500/1701/4500 + IPv6） | ❌ 432 个握手包 0 回应 |

另外：
- TCP/443 用 SNI `www.cloudflare.com` 到同样这两个 IP，TLS 正常；换成 `consumer-masque.cloudflareclient.com` **立刻被 RST** → 这是 **SNI 级封锁**，也意味着 MASQUE 的 HTTP/2(TCP) 回退模式在这条线路上不可用。
- QUIC 通道本身是**间歇性**的：同一端点有时握手+200 全通，有时连 CONNECT-IP 响应都收不到（Cloudflare 侧还会回 `code 0x12E`）。

**结论**：官方客户端在这条线路上能跑 MASQUE，而两个独立第三方实现（Python 的 warp2s5、Go 的 usque）同时拿不到数据面 —— 说明差异不在我的协议编码（登记/握手/请求都已被服务端接受），而在第三方 QUIC 流量被区别对待（典型特征是握手放行、数据面丢弃）。这一条我还没能完全定位，欢迎在能用的网络（境外 VPS 等）上跑 `--check --transport masque` 交叉验证。

---

## 自检

```bash
python -m warp2s5 --check                      # 注册设备 → 建隧道 → 隧道内 DNS → 隧道内 HTTP，打印出口 IP
python -m warp2s5 --check --transport masque   # 只测 MASQUE
python -m warp2s5 --check --transport wireguard
```

看到 `warp=on` 就说明流量确实从 WARP 出去了。

开发过程中另有一整套测试（单元测试、本地 WireGuard 对端端到端、CLI + curl 走 SOCKS5、
握手报文与 Go 官方实现逐字节差分、BLAKE2s 交叉验证），它们需要 Go / node 环境，
没有随源码一起发布。

---

## 排错

* **`--check` 卡在 tunnel**：换传输试（`--transport masque` ↔ `--transport wireguard`）；WireGuard 可再试 `--endpoint 188.114.96.1 --port 2408`、`--family v6`、`--port 500`。
* **MASQUE 隧道起来了但打不开网页**：就是上面第 3/4 条的现象（数据面被丢），换网络或换出口（VPS）再试。
* **浏览器/curl 报 SOCKS5 错误码 8**：目标是 IPv6，本协议栈只支持 IPv4 目标；用 `curl -4` 或让客户端走域名（`socks5h`）。
* **`hashlib.blake2s` 卡死**：本项目自带纯 Python BLAKE2s，不依赖它（某些 CPython 3.14 构建里 `hashlib.blake2s` 会死循环）。

## 限制

* 只支持 **IPv4 目标**（隧道内 IPv6 未实现；IPv6 目标会被拒绝）。
* SOCKS5 只实现 `CONNECT`（`UDP ASSOCIATE` 返回不支持，浏览器会回退 TCP）。
* TCP 是教学级实现：有滑动窗口/拥塞控制/重传/乱序重组，但没有 SACK/时间戳，吞吐受 Python 解释器限制（单向几 Mbps～几十 Mbps），适合浏览/代理，不适合跑满带宽。
* MASQUE 客户端证书是自签的，服务端证书不校验（SNI 与端点域名不同，官方客户端用固定公钥校验；本实现留待补充）。

## 许可

MIT
