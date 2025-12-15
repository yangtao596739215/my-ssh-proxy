## VS Code Remote-SSH 运行原理概要

### 目标
让 VS Code 客户端像操作本地一样操作远端工作目录。核心是：在远端运行一套 VS Code Server，再用 SSH 隧道把 VS Code 协议通道和端口安全地传回本地。

### 核心流程
1) **建立 SSH 连接并准备隧道**
   - VS Code 使用本地 `ssh` 客户端，默认开启动态或本地端口转发（依赖 `direct-tcpip` channel）。
   - 要求服务端支持标准 SSH：认证、公钥/密码、`direct-tcpip`、`session`、`exec`、`sftp`。
2) **上传/拉起 VS Code Server**
   - 通过 `sftp`/`scp` 将 VS Code Server 包推送到远端 `~/.vscode-server`。
   - 通过 `exec`/`session` 通道执行启动脚本，启动后输出 `listeningOn=<host:port>` 等信息。
3) **端口转发与通信**
   - VS Code 在本地开一个转发（SOCKS 或 -L），把远端 Server 监听端口映射回本地。
   - 之后的 UI/编辑/FS 操作都通过该隧道传输 VS Code 自有协议。
4) **特性支撑**
   - 终端：需要 `session` + `pty-req`，可多路复用。
   - 文件：依赖 `sftp`（或走 Server 内部文件服务）。
   - 调试/端口转发：继续复用 `direct-tcpip`。

### 与 SSH 协议的关键点
- **direct-tcpip**：VS Code Remote-SSH 的隧道基石，缺失或被禁会导致 “Waiting for port forwarding” 等错误。
- **session/pty/shell/exec**：用于启动 Server、提供集成终端。
- **subsystem sftp**：用于上传安装包/同步文件；没有 sftp 会导致安装或文件操作失败。
- **多路复用**：SSH 在单 TCP 连接上承载多个 channel，降低连接数，配合 keepalive 保持稳定。

### 故障常见点
- 服务器禁用了 `direct-tcpip`：无法建立转发，连接卡住或报 “unknown channel type”。
- 没有 sftp：Server 包无法上传，或文件浏览不可用。
- 认证/known_hosts 冲突：公钥变更未清理，导致拒绝连接。
- 防火墙/网关拦截：22/自定义端口未放行，或中途丢包导致隧道掉线。

### 与本项目的关系（my-ssh-proxy）
- 项目为 direct/proxy 双端提供 SSH 兼容隧道，server 负责转发；client/backen 可作为 VS Code 的 SSH 目标。
- 为兼容 VS Code，在内置 ssh server 中补充了：
  - `direct-tcpip` 支持（动态/本地转发）
  - `session` + `pty` + `shell`
  - `subsystem sftp`
- 使用时确保：VS Code 连接的端口就是 client 暴露的端口；backen 已在线并注册好 backend_key；server 允许 `direct-tcpip`。

