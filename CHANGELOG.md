# 更新日志（CHANGELOG）

`ncc-registry` —— 内网托管节点：单二进制 + 可嵌入的 Go 库。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。
「怎么用」看 [`README.md`](README.md)；**本文件只回答「这一版比上一版多了什么」**。

> 本仓库原先寄居在 [`ncc`](https://github.com/fusedmodel/ncc) 的 `ncc-registry/` 目录下、
> 与 CLI 共用一份 CHANGELOG。独立出来后**从 `0.1.0` 起走自己的版本线** ——
> 所以 `0.1.0` 记的是「独立那一刻已经具备的全部能力」，不是新增功能。

## [0.1.0] — 2026-09-24

首个独立版本：仓库从 `ncc` 拆出来（`module github.com/fusedmodel/ncc-registry`），
既发布二进制，也发布可被 `go get` 的库。

### 变更 · 拆分为独立仓库与独立库

- **module 路径**：`github.com/fusedmodel/ncc/ncc-registry` → `github.com/fusedmodel/ncc-registry`。
  旧路径下所有代码都在 `internal/`，**模块外一个包也 import 不到** —— 也就是说作为库它从来就是不可用的。
- **五个包提到顶层**，成为公开 API：`config` · `model` · `storage` · `store` · `httpapi`；
  `p2p` 与 `secretbox` 留在 `internal/`（`httpapi` 照旧 import 它们，同模块内合法，外部拿不到）。
- **新增 `httpapi.NewServer` 与 `(*Server).Close`**：`NewRouter` 只返回路由，拿不到句柄，
  于是它启的后台循环（worker 心跳 / master 清理过期 worker / 可被打洞入口）没有任何停止机制 ——
  进程退出无所谓，但作为库反复创建就会一直漏协程。`NewRouter` 保留原签名，内部委托给 `NewServer`。
- 仓库自带 CI（gofmt / vet / build / 冒烟）与 Release（六个平台的二进制 + `checksums.txt` + GHCR 镜像）。

### 修复 · 二进制入口 `cmd/ncc-registry` 一直不存在

`README.md`、`deploy/Dockerfile`、`scripts/smoke.sh` 三处都在 `go build ./cmd/ncc-registry`，
但**这个目录从来没有被提交过**（初始提交 22 个文件全是 `internal/`）—— 也就是说
文档里的构建命令一直是坏的，二进制压根编不出来。现已补上 `cmd/ncc-registry/main.go`
（`config.Load` → `store.Open` → `storage.NewLocal` → `httpapi.NewServer`，含优雅退出）。

### 修复 · Windows 下制品 URL 带反斜杠（`storage.Local`）

`safeName` 用 `filepath.Clean` 清洗对象名，而对象名是**斜杠分隔**的标识（它要进 URL、
也要在 master / worker 之间原样传递）。Windows 上 `filepath.Clean("/a")` 得到 `\a`，
`TrimPrefix(clean, "/")` 再剥不掉那个反斜杠，于是 `PublicURL` 产出 `…/blobs/\a` 这种非法地址；
把它填进 JSON 请求体就变成 400。现改用 `path`（斜杠语义）清洗、只在落盘时 `filepath.FromSlash`。
顺带拒绝含 `\` 或 `:` 的对象名。**macOS / Linux 上行为完全不变。**

### 修复 · 冒烟脚本在 Windows 上的 3 项路径断言

`scripts/smoke.sh` 拿 `NCCR_*` 的 Git-Bash 路径（`/tmp/xxx`）比对接口回显的
Windows 绝对路径（`C:\Users\…`），必然不等。属脚本的路径显示差异，不是被测行为；
CI 跑在 ubuntu 上不受影响。当前共 **167 项检查**。

### 能力 · 制品托管与多节点

- 账号 / 命名空间 / 发布 / 检索 / 下载 / 分发；`sha256` 校验、`@命名空间/slug` 稳定引用。
- **master / worker**：权威在 master（账号、制品、节点目录）；worker 是边缘托管点，
  自己也托管制品与节点并定期上报目录。客户端只认 master 一个地址 ——
  查目录看聚合结果，下载时 master 去持有者那里把字节代理回来。
- **集群写**：把条目**分发**（replicate）到 worker，下架时**回收**（revoke）副本。
- 存储三处可分别指定：`NCCR_DATA_DIR` / `NCCR_BLOB_DIR` / `NCCR_DB_PATH`
  （内网常见诉求：字节放 NAS、库存本地 SSD）。

### 能力 · 托管节点与 Agent 发现

- 用户把内网的 Agent / 服务**注册 + 心跳**托管进来，声明「我是谁、在哪、能干什么」。
- 同一信任域内互相发现、收进连接表、按区域聚合；`/api/nodes/route` 回答
  「这个能力该找哪个节点要」。

### 能力 · 接入与授权（连接 ≠ 授权）

- 一条内网短链（或 key+secret）就能把一个 Agent 加进来，兑换出的是**最小权限的节点令牌**。
- 私有制品 / 私有节点 / 非公开配置要显式 `grant`，撤销立即生效（支持按命名空间限定）。

### 能力 · 配置托管

- 团队的网络 / 基础设施 / Agent 配置作为一等资源：版本历史、回滚、按环境成组拉取。
- 10 种类型、7 种格式、单条上限 128 KB；`secret=true` 的配置**静态加密**
  （AES-256-GCM，密钥由本节点 `jwt-secret` 派生，密文前缀 `enc:v1:`）——
  只备份数据库是安全的；反过来换机器 / 丢数据目录就解不开（设计意图，不是缺陷）。

### 能力 · 分享链接与节点治理

- **分享**：把一条制品变成临时下载地址发出去，对方不用登录、不用装 CLI；可限次 / 限时 / 撤销。
- **治理（admin）**：本节点第一个注册的账号自动成为管理员，同时签发机器凭据 `AK-…`；
  管用户 / 节点 / 服务（禁用启停、重置密码、摘除、归档），每个动作都进审计。

### 能力 · 节点侧 P2P（打洞条件判断面）

- `GET /api/p2p/self`：在**这台机器**上出 NAT 画像与结论；`POST /api/p2p/check`：
  与一个已知映射地址**真实对打**（0 字节，不传业务）；`GET|POST /api/p2p/serve`：
  开一个只应答 STUN Binding 请求的可被打洞入口（默认**关**，`NCCR_P2P_SERVE=1` 才随服务启动）。
- **实测结论**：纯被动应答在「地址/端口相关过滤」的 NAT 上收不到任何包 ——
  过滤孔必须自己先发才开，所以入口默认带**反向打洞**（每 300 ms 向对端发一个 Binding 请求）。
- 字节面（真正的数据传输）尚未接上，见 `ncc` 仓库的 `prd/ncc-p2p-data.md`。
