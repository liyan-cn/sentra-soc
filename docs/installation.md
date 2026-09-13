# 安装指南

## 运行条件

- Python 3.11–3.13；Linux 用于正式部署，Windows 可运行 API、测试及文件采集。
- 单机 SQLite WAL，不支持多节点共享写入，不要放在 NFS/SMB 共享目录。
- 首次启动没有设备和日志时，空图表属于正常状态；系统不会自动制造示例告警。
- 日志接收器不包含在 API 中。先用 rsyslog 等把设备 Syslog 写成文件，再配置采集。

## 方式一：Docker Compose

在 GitHub 下载源码 ZIP 并解压，或克隆你自己的仓库，然后进入包含 compose.yaml 的目录：

```bash
cp .env.example .env
cp config/devices.yaml.example config/devices.yaml
mkdir -p logs
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

把生成的随机值填入 `.env` 的 `MONITOR_ADMIN_TOKEN`，不要上传该文件。
未填写时 Compose 会拒绝启动。初次启动不要开启任何自动防火墙执行。

```bash
docker compose config --quiet
docker compose up -d --build api action maintenance
docker compose logs --tail=100 api
```

打开 http://127.0.0.1:5001 ，使用自己的令牌登录；大屏路径为 `/display`。
默认端口仅本机可见；远程使用请通过 SSH 隧道或自行配置 HTTPS 反向代理。

在 `.env` 设置 `MONITOR_LOG_ROOT`（宿主机日志目录）和设备 ID；在
`config/devices.yaml` 设置容器内 `/logs/...` 路径。只有确实写入日志的设备才应开启：

```bash
docker compose --profile collectors up -d collector
docker compose --profile vpn up -d vpn
```

一个 collector 服务处理一个设备。多设备可复制该服务并给每个服务指定不同 ID；不要
让两个采集器共用同一 ID。API 和采集器读取同一设备配置，避免看板找不到接入设备。

Compose 自动读取 `.env`，Python 原生启动不会。目录映射的读权限也必须授予容器用户。
`docker compose down` 保留数据库卷；**不要执行 `down -v`，它会删除数据卷**。

## 方式二：Python 原生运行

Linux/macOS：

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
cp config/devices.yaml.example config/devices.yaml
export MONITOR_CONFIG="$PWD/config/base.yaml"
export MONITOR_DEVICES_CONFIG="$PWD/config/devices.yaml"
export MONITOR_DB_PATH="$PWD/data/monitor.db"
export MONITOR_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
monitor3 migrate
monitor3 doctor
monitor3-api
```

Windows PowerShell（无需修改系统执行策略）：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item config/devices.yaml.example config/devices.yaml
$env:MONITOR_CONFIG = "$PWD/config/base.yaml"
$env:MONITOR_DEVICES_CONFIG = "$PWD/config/devices.yaml"
$env:MONITOR_DB_PATH = "$PWD/data/monitor.db"
$env:MONITOR_ADMIN_TOKEN = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
.\.venv\Scripts\monitor3.exe migrate
.\.venv\Scripts\monitor3.exe doctor
.\.venv\Scripts\monitor3-api.exe
```

原生运行时把设备日志路径改为本机绝对路径；`/logs` 只是容器挂载示例。
各后台服务需要独立进程，且使用相同环境变量：`monitor3-action`、
`monitor3-maintenance`、`monitor3-collector --device huawei-ips-01`、
`monitor3-vpn --device vpn-01`。API 启动不代表采集进程已启动。

Linux 持久运行可参考 `deploy/systemd/` 的通用 `/opt/monitor3` 单元。
部署者需创建 monitor3 用户、创建并授权 `/var/lib/monitor3`、准备
`/etc/monitor3/monitor3.env`，并根据实际安装目录修改单元；不要直接套用 `*-home.service`。
配置文件和凭据文件限服务用户读取。生产 API 使用 Gunicorn，Windows 使用 Waitress。

## 验收、备份与升级

```bash
python -m pytest -q
monitor3 doctor
monitor3 backup create
monitor3 backup verify --input /absolute/path/to/backup.db
monitor3 backup rehearse --input /absolute/path/to/backup.db
```

`/health/live` 是进程存活检查，`/health/ready` 的必需后台服务需在配置里声明。
备份需检查成功清单和隔离恢复演练，不能以“定时器已启用”代替成功。
大数据库的随机读性能会显著影响校验；当前检查有 10 分钟超时，超时意味着未验证。

升级前创建并验证备份，记录当前版本，停止所有写入进程，再安装新版本并执行
`monitor3 migrate`，最后启动后台进程及 API。不要在生产运行状态下恢复数据库。
确需恢复时先停止全部进程，再运行
`monitor3 backup restore --input /absolute/path/to/backup.db --confirm`。
不可只拷贝正在写入的 SQLite 主文件而忽略 WAL。

## 常见问题

- 401：令牌未设置、失效或浏览器使用了旧令牌；不要把令牌写进 URL。
- 源无数据：检查设备 ID、实际文件路径、读权限、采集进程和最近采集时间。
- VPN 无公网地址：需要登录日志中的 Client IP，单凭虚拟 IP 不能反推出用户公网 IP。
- 有采集但无告警：普通允许流量和识别样本不等于安全告警。
- 图表仍是旧版：强制刷新页面，检查反向代理缓存及部署的资源版本。
- 写入锁冲突：不要启动重复采集器，不要使用网络共享 SQLite；先检查磁盘和后台批处理。
