# 分层配置

Monitor 3.0 首先加载 wheel 内置的安全默认值，再递归合并 `MONITOR_CONFIG` 指定的用户文件。
因此生产配置只需要声明与默认值不同的部分，新版本增加默认字段时无需复制整份 `base.yaml`。
字典按字段合并，列表（例如 `devices`、`hosts` 和通知 `channels`）整体替换。

Linux 部署可以复制 `config/production.yaml.example` 到 `/etc/monitor3/production.yaml`，再设置：

```bash
MONITOR_CONFIG=/etc/monitor3/production.yaml
MONITOR_DEVICES_CONFIG=/etc/monitor3/devices.yaml
```

敏感值必须通过环境文件注入，不得写入 YAML。策略文件、known_hosts、数据库和数据目录在生产
模板中均使用绝对路径，避免 systemd 工作目录变化导致读取错误。

Compose 可以在 `.env` 中设置：

```text
MONITOR_CONFIG_PATH=/opt/monitor3/config/production.yaml
```

容器内路径必须位于已经挂载的 `./config` 目录。修改配置后先运行 `monitor3 doctor`；正式切流
前运行 `monitor3 release-check --require-backup`。
