# 控制器运维

## 职责与构建

可执行文件入口为 `cmd/xdrop-controller`，实现位于 `core/`，控制台源码位于 `../console/`。在仓库根目录运行 `./scripts/build-controller.sh all`：web 构建控制台，go 带 `-tags webui -trimpath` 编译，all 依次执行两步。缺少 `core/webui/build/index.html` 时 go 步骤会拒绝；不带 tag 的构建只嵌入占位页面。

`XDROP_SKIP_NPM_CI=1` 明确复用已有前端依赖；默认执行 `npm ci`。在 `controller/` 可用 `make all` 依次构建前端和 Go，以及 `make web`、`make build`、`make run CONFIG=/absolute/path/controller.example.yaml`、`make test`、`make clean`、`make dev CONFIG=...`。`make deps` 下载 Go 模块并安装控制台依赖；构建路径不执行 `go mod tidy`。

## 配置

| 键 | 必填值 |
|---|---|
| `listen` | 主机与端口；端口 1..65535；示例 `127.0.0.1:8000` |
| `database` | SQLite 文件绝对路径 |
| `secret_key_file` | 主密钥文件绝对路径 |

配置没有默认值。未知字段、重复键和多份 YAML 文档都会被拒绝。节点已存数据库，因此拒绝 `nodes`；周期已移至设置，因此拒绝 `reconcile_interval`。浏览器会话应通过同机 HTTPS 反向代理访问回环监听。

主密钥文件权限必须为 0600，内容是 base64 编码的 32 字节密钥。节点 API 密钥使用 AES-256-GCM 加密，以节点名称作为附加认证数据；主密钥缺失或无效时拒绝启动。单个节点密钥无法解密时仍显示 `key_unreadable`，且不向该节点发送请求。

## 初始化与 CLI

`-config <绝对文件路径>` 必须放在子命令前。先初始化主密钥，再添加管理员；完整命令见[部署指南](../GETTING_STARTED.zh.md)。

| `-config <file>` 后的命令 | 行为 |
|---|---|
| `secret-key init` | 创建 0600 主密钥文件；拒绝覆盖；不开数据库 |
| `user add <name>` | 读取密码并创建管理员 |
| `user passwd <name>` | 重置密码并撤销会话 |
| `node add <name> --url <url> --key-stdin` | 从 stdin 读取一行密钥来登记节点 |
| `node update <name> [--url <url>] [--key-stdin]` | 修改 URL 和/或密钥 |
| `node delete <name>` | 删除已存节点 |

终端密码输入两次且无回显；管道输入读取一行。密码必须为 10..72 字节。CLI 成功返回 0，操作错误返回 1，命令语法错误返回 2。节点 CLI 写入用于控制器停止期间；运行时使用 UI/API，因为 CLI 不刷新运行实例的内存客户端。

## 进程管理

在仓库根目录使用 `scripts/manage-controller.sh start|stop|restart|status|logs`。通过绝对路径 `XDROP_CONFIG`、`XDROP_RUN_DIR` 覆盖默认 `controller/config.yaml`、`controller/run`。运行文件为 `service.pid`、`service.exit`、`service.log`，管理操作使用 `manager.lock`。

脚本记录二进制 PID，发送信号前核对精确的二进制/配置命令。`stop` 发送 SIGTERM，最多等待 30 秒，不升级为 SIGKILL；控制器以 10 秒期限排空 HTTP，关闭事件流、停止工作任务并关闭存储。`status` 运行时返回 0、停止时返回 3；`logs` 跟踪日志。身份或锁校验失败时，应先检查记录的进程再手工修复运行文件。start 不执行初始化。

## 鉴权与日常操作

用户通过服务端会话登录；票据是不透明值，不是 JWT。机器使用命名 API 凭证，通过 `Authorization: Bearer <machine-key>` 提供。不要同时提交会话 cookie 与机器请求头。管理员路由要求 admin 用户会话；operator 会话可按 [API 路由表](API.zh.md)管理规则并读取运维数据。

在节点/设置入口登记或测试节点，编辑规则和白名单，检查逐规则下发、容量、流量历史及审计。节点密钥只作为 API 写入输入，不出现在列表或详情输出。轮换时修改节点配置并重启该节点，再 PATCH 控制器登记项为同一密钥；API 替换该客户端，无须重启控制器。两次修改之间可能暂时鉴权失败。

对账周期通过 `reconcile_interval_minutes` 设置，默认 15 分钟、范围 1..1440。仅对在线、协议兼容、未过载且该侧没有待完整同步/脏数据的合格节点执行；持续漂移会暴露状态，不承诺无条件修复。

## 升级与恢复

复制备份数据库和主密钥文件前先停止控制器，并保留配套二进制和配置。启动会打开/迁移存储并准备已存规则。没有降级命令；回滚需先停止，再恢复兼容的二进制、数据库和主密钥备份组合。

当前节点客户端仅接受同步协议 11。升级时保持组件兼容；协议不匹配的节点标记为不兼容并停止同步。节点重启会清空策略，直到规则及白名单完整快照恢复；确认每台恢复后再处理下一台。

主密钥丢失时，将 `secret_key_file` 指向新路径、初始化并重启，再通过 PATCH 重新提交各节点 API 密钥。这能修复不可读节点，无法恢复旧密钥明文。没有自动重建或轮换主密钥功能。
