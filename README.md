# Sentra SOC · 哨域

让分散的安全日志，成为看得见的安全态势。

Self-hosted lightweight security operations platform. 基于 Monitor 3.0，保留 `monitor3` 命令和配置名称以兼容现有部署。

<img width="2559" height="1344" alt="image" src="https://github.com/user-attachments/assets/05bbe39e-0a89-4147-a465-db4f8361f498" />

<img width="2559" height="1347" alt="image" src="https://github.com/user-attachments/assets/da071565-5925-4651-8551-89a4020b66b8" />

当前维护版本：**3.0.1** · [更新与升级说明](docs/release-3.0.1.md)

轻量级、可自部署的安全监控与态势展示平台。集中处理设备日志、告警研判、VPN 活动和资产状态，适合单节点部署及二次开发。

> 默认关闭自动防火墙执行、通知和 AI。首次部署无真实数据时看板为空，不会生成伪造告警。请先在测试环境验证，勿直接连接未经授权的设备。

## 从这里开始

- [完整安装指南：Docker / Linux / Windows](docs/installation.md)
- [适配自己的设备、日志路径和网络环境](docs/environment-adaptation.md)
- [GitHub 发布前检查](docs/github-publishing.md)
- [分层配置](docs/configuration.md) · [架构](docs/architecture.md) · [扩展插件](docs/plugin-development.md)

## 功能

- 多厂商 Syslog 文件采集、解析失败记录、轮转恢复、采集与告警分开统计。
- 策略研判、人工审核、白名单、可选自动处置及操作审计。
- VPN 近期活动与登录来源关联；公网 IP 必须来自设备实际登录日志。
- 资产在线监测、受限内网网段发现、后台任务进度及失败重试。
- 安全态势大屏、小时趋势图、来源地区关联与基础设施心跳。
- Web 数据保留设置、SQLite 备份校验与隔离恢复演练。

## Docker 快速启动

下载并解压本仓库，在项目根目录执行：

```bash
cp .env.example .env
cp config/devices.yaml.example config/devices.yaml
mkdir -p logs
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

把生成的随机值填入 `.env` 的 `MONITOR_ADMIN_TOKEN` 后：

```bash
docker compose config --quiet
docker compose up -d --build api action maintenance
```

访问 **http://127.0.0.1:5001**，使用自己的令牌进入控制台；展示大屏地址为 `/display`。
日志采集及 VPN 服务按需启用，详见[安装指南](docs/installation.md)。

## 项目结构

```text
src/monitor/       API、采集器、解析器、任务、数据库迁移和前端资源
config/            通用配置和设备示例；私有配置不提交
deploy/            可参考的服务、反向代理与监控模板
tests/             使用临时数据库和模拟依赖的回归测试
docs/              安装、适配与开发说明
.github/workflows/ 测试、依赖检查和发行产物工作流
```

## 开发与验证

要求 Python 3.11–3.13。创建虚拟环境后：

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
monitor3 plugins
monitor3 doctor
```

Node.js 可选，用于运行 `node tests/wall_chart_check.cjs` 检查大屏绘制逻辑。
GitHub CI 的实际结果以你自己仓库执行的工作流为准；本地测试不代表所有部署环境已验证。

## 使用边界

SQLite WAL 仅支持单节点写入，不支持 PostgreSQL 或多节点共享数据库。
大量日志需要评估磁盘随机读性能、采集延迟和清理吞吐；备份超时不等于校验成功。
当前前端时间统一显示为 Asia/Shanghai，其他时区适配须同步调整显示与解析。
公网地址定位可能向第三方查询源 IP，部署前应评估隐私要求并配置自己的服务。

严禁上传真实日志、数据库、用户信息、服务器凭据或现场部署资料。
不要直接对公网开放 HTTP 管理端口；通过 HTTPS 可信反向代理访问。

## 贡献与许可

欢迎按 [CONTRIBUTING.md](CONTRIBUTING.md) 提交问题和改进。
漏洞或敏感配置问题请参考 [SECURITY.md](SECURITY.md)，不要发到公开 Issue。

沿用项目现有 [Apache-2.0 许可声明](LICENSE)。公开发布前，维护者需确认全部代码和素材的授权归属。
