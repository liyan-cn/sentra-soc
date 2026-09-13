# 适配自己的环境

| 配置项 | 用途 | 建议 |
| --- | --- | --- |
| MONITOR_CONFIG | 主 YAML 绝对路径 | 原生启动显式设置 |
| MONITOR_DEVICES_CONFIG | 设备 YAML 绝对路径 | 所有进程读取同一文件 |
| MONITOR_DB_PATH | SQLite 文件绝对路径 | 本地持久磁盘，单节点 |
| MONITOR_ADMIN_TOKEN | 初始化管理员令牌 | 随机生成，环境变量注入 |
| MONITOR_API_HOST / PORT | 原生 API 监听 | 默认 127.0.0.1:5001 |
| MONITOR_CONFIG_PATH | Compose 容器配置路径 | 只供 compose.yaml 插值 |
| MONITOR_LOG_ROOT | Compose 宿主机日志目录 | 容器内固定挂载 /logs |

YAML 覆盖包内安全默认值；列表（devices、hosts）整体替换，不自动按 ID 合并。
相对数据路径按配置文件的上两级目录解析；生产部署优先写绝对路径。
默认没有资产，不会自动扫描任意网段；网段发现需在 Web 主动提交，仅允许 RFC1918、最多 /24。

## 按顺序接入

1. 安装并验证 API；防火墙保持 `mode: disabled`，通知和 AI 保持关闭。
2. 由 rsyslog 接收日志，确认时间戳、源设备和日志格式；与设备建立发送配置需由设备管理员处理。
3. 用 `monitor3 plugins` 查看实际支持的解析器。填写 `id/source/parser/log_glob`，避免把 VPN-only 配置交给通用 collector。
4. 先运行 `monitor3 replay --device <ID> --file <日志路径> --limit 100` 做离线解析检查，再启动采集进程。
5. 核对采集量、告警量及来源时间；确认规则后再评估通知和自动处置。

当前 Web 时间显示统一使用 Asia/Shanghai；修改 `app.timezone` **不会自动改变所有前端时间显示**。
需要其他时区时应同步修改前端 formatter 和解析器时间策略并测试，不能盲目把真实设备时钟偏差当时区转换。

公网地址定位默认通过 IP 查询服务进行；启动采集前评估源 IP 对外查询的隐私要求，
隔离环境可配置内部兼容服务或自定义 geolocation 插件。定位服务不能生成不存在的 VPN 原始公网 IP。

## 生产边界

- 仅部署者拥有授权的设备和网段；不要对公网开放无 TLS 的管理端口。
- `trusted_proxy_hops` 默认 0，仅按可信代理的实际层数设置，避免伪造来源地址。
- 不内置设备密码、SSH 私钥或长期公开令牌。SSH known_hosts 需由管理员核对指纹后维护。
- 安全日志保留天数可由管理员在 Web 设置；缩短后数据会循环删除。数据库保留不等于原始 Syslog 保留。
- 保留期限按组织要求配置，不把某个现场的“一周”作为所有用户的合规要求。
- 不支持 PostgreSQL 多节点写入；大流量部署先压测存储及清理吞吐，再决定生产规模。
