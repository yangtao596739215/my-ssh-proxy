## my-ssh-proxy 使用说明

本项目实现了一个基于 SSH 协议的中继服务，整体拓扑为：

- **server**：SSH 中继服务，监听 TCP 端口并在本机通过 Unix Socket 串联前端 client 与后端 backen。
- **backen**：后端注册代理，连接到 server，在 server 端暴露一个 Unix Socket，并把经由该 Socket 的流量转发到本机业务端口。
- **client**：前端本地代理，连接到 server，监听本地 TCP 端口，将本地连接通过 SSH `direct-streamlocal@openssh.com` 通道转发到 server 上指定的 Unix Socket。

### 1. 自动密钥目录说明

所有组件（server / backen / client）统一使用当前用户目录下的：

- 目录：`$HOME/.ssh/myproxy`
- 文件：
  - `host.key` / `host.pub`：server 的 SSH Host Key
  - `direct.key` / `direct.pub`：client 使用的 SSH 身份
  - `proxy.key` / `proxy.pub`：backen 使用的 SSH 身份

特性：
- 如果文件不存在，会自动生成 **Ed25519** 密钥对并写入该目录。
- 如果文件已存在，则直接复用，不需要手动管理。

### 2. 编译

在项目根目录执行：

```bash
go build ./...
```

将得到三个可执行文件（也可以用 `go run` 直接运行）：

- `cmd/server`
- `cmd/backen`
- `cmd/client`

### 3. 启动顺序与典型用法

假设目标：将后端机器上的 `127.0.0.1:9000` 业务端口，通过中继暴露为前端本地的 `127.0.0.1:9000`，并且一个后端允许多个前端 client 同时接入。

#### 3.1 启动 server

在中继节点（可以是本机）执行：

```bash
go run ./cmd/server \
  -port 2222 \
  -socket-dir /tmp/my-ssh-proxy \
  -allow-bootstrap=true
```

参数说明：
- `-port`：SSH 监听端口，默认 `2222`。
- `-socket-dir`：server 本地 Unix Socket 存放目录，默认 `/tmp/my-ssh-proxy`。
- `-allow-bootstrap`：
  - 为 `true` 时：当某个用户（`direct` 或 `proxy`）第一次连接且没有已知公钥时，会 **接受该次连接的公钥并记忆**，后续连接用此公钥校验。
  - 首次联通、密钥初始化阶段建议开启；稳定使用时可关闭加强安全。

server 启动后会：
- 在 `$HOME/.ssh/myproxy` 下自动生成/加载 `host.key`。
- 在同目录下生成/加载 `direct.pub`、`proxy.pub` 作为初始白名单公钥。

#### 3.2 启动 backen（后端注册代理）

在后端机器（能访问业务端口 `127.0.0.1:9000` 且能连到 server:2222）执行：

```bash
go run ./cmd/backen \
  -server 127.0.0.1:2222 \
  -user proxy \
  -local 127.0.0.1:9000 \
  -sshserver
```

参数说明：
- `-server`：server 的 `host:port`，默认 `127.0.0.1:2222`。
- `-user`：SSH 用户名，后端固定为 `proxy`。
- `-backend-key`：后端唯一标识（**随机字符串，要求在所有后端之间不重复**），client 通过该 key 来定位到具体后端。
- `-local`：后端本地业务地址，例如 `127.0.0.1:9000`。

backen 行为：
- 在本机 `$HOME/.ssh/myproxy/proxy.key/.pub` 自动生成或加载密钥对。
- 以 `proxy` 身份通过 SSH 连接 `-server`。
- **先发送 `update-authorized-key` 请求**，把 `proxy.pub` 公钥同步给 server。
- 向 server 请求注册 `-backend-key`，server 内部会基于该 key 在 `-socket-dir` 下创建一个 Unix Socket 并维护映射。
- 之后：任何 client 使用相同 `-backend-key` 的连接，都会经由 SSH 通道转发到本机 `-local`。

#### 3.3 启动 client（前端本地代理）

在前端机器执行：

```bash
go run ./cmd/client \
  -server 127.0.0.1:2222 \
  -backend-key my-backend-1 \
  -listen 127.0.0.1:9000
```

参数说明：
- `-server`：server 的 `host:port`。
- `-backend-key`：要访问的后端标识，需与 backen 侧的 `-backend-key` 完全一致。
- `-listen`：client 在本地监听的地址，例如 `127.0.0.1:9000`。

client 行为：
- 在本机 `$HOME/.ssh/myproxy/direct.key/.pub` 自动生成或加载密钥对。
- 以 `direct` 身份通过 SSH 连接 `-server`。
- **先发送 `update-authorized-key` 请求**，把 `direct.pub` 公钥同步给 server。
- 本地监听 `-listen`，每当有新连接：
  - 使用通道类型 `direct-streamlocal@openssh.com`，并在 payload 里携带 `-backend-key`。
  - server 根据 `backend-key` 找到对应的后端 Unix Socket，将双向流量在本地 TCP 连接与该后端通道之间做双向拷贝。

#### 3.4 多 client / 多窗口场景

- 同一个后端，只要使用同一 `-backend-key` 启动 backen，一次启动即可。
- 多个前端窗口可以分别启动多个 client：
  - 可以都监听同一个端口（例如 `127.0.0.1:9000`，注意端口占用），或各自不同端口。
  - 只要 `-backend-key` 相同，就会被路由到同一个 backen，**会话之间互不影响**。

最终效果：
- 前端应用只需要访问 `127.0.0.1:9000`（client 的监听端口），即可经过 SSH 中继，到达后端 `127.0.0.1:9000`。

### 4. 公钥同步与认证逻辑

- server 维护两类用户：
  - `direct`：前端 client 使用的 SSH 用户。
  - `proxy`：后端 backen 使用的 SSH 用户。
- 每个用户的公钥来源：
  1. 启动时从 `$HOME/.ssh/myproxy/direct.pub` / `proxy.pub` 读取作为初始白名单。
  2. 运行过程中，client / backen 会在建立 SSH 连接后发送自定义全局请求：
     - 类型：`update-authorized-key`
     - 载荷：`protocol.UpdateAuthKeyRequest{User, AuthorizedKey}`  
     server 解析后将公钥追加到内存白名单。
  3. 若开启 `-allow-bootstrap`，当某用户尚无白名单公钥时，第一次连接的公钥会被接受并记忆。

认证流程：
- SSH 握手阶段由 `publicKeyCallback` 对 `direct` / `proxy` 用户的公钥进行匹配（包含 bootstrap）。
- 连接建立后，才会处理 `update-authorized-key`、`streamlocal-forward` 等请求。

### 5. 调试与常见问题

- **查看密钥是否生成：**
  - 检查：`ls $HOME/.ssh/myproxy`
  - 应包含：`host.key/.pub`、`direct.key/.pub`、`proxy.key/.pub`

- **修改或重置密钥：**
  - 可以删除对应文件，例如：
    ```bash
    rm ~/.ssh/myproxy/direct.*
    ```
  - 下次运行 client 时会自动重新生成。

- **安全建议：**
  - `-allow-bootstrap` 仅在受控环境 / 首次初始化时开启，完成后可关闭。
  - `$HOME/.ssh/myproxy` 目录权限默认为 `0700`，请不要放在共享目录下。

## 为什么使用 Unix Socket

- **对齐 SSH 标准转发语义**：复用 `streamlocal-forward@openssh.com`（streamlocal 转发），后端用远端转发暴露 Unix Socket，server 直接监听 socket 并为每个连接开新 channel，无需自定义协议或 fd 映射。
- **就绪与生命周期可观测**：socket 文件存在且可 accept 即表示就绪/存活；断开时关闭 socket，前端路由自动收敛，不必维护复杂的内存态映射与清理。
- **解耦 direct 与 backend**：双方仅通过 socket 路径桥接，direct 不需要知道后端连接细节，backend 只管暴露 socket。
- **多进程/多语言友好**：任意进程/语言只要能连本地 Unix Socket 即可，不依赖特定 SDK 或内部 channel id。
- **安全与性能**：仅本机可见，可用权限/目录隔离控制访问；绕过 TCP 协议栈，回环开销更低。
- **清理与重连确定性**：SSH 断开 → socket 关闭 → 路由摘除；重连同名 socket 即可恢复，无需还原内存状态。


