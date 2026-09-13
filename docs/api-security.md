# API 安全配置

Monitor 3.0 默认限制请求体为 1 MiB，并为响应添加 CSP、禁止嵌入、MIME 嗅探保护、
最小权限浏览器策略和 API 禁止缓存响应头。受保护接口按来源地址进行进程内滑动窗口限流。

```yaml
api:
  max_request_bytes: 1048576
  auth_rate_limit_per_minute: 120
  token_usage_update_seconds: 300
  trusted_proxy_hops: 0
```

`auth_rate_limit_per_minute: 0` 可以关闭应用层限流。多实例部署时仍应在入口网关配置共享限流。

只有 API 确实位于固定数量的可信反向代理后方时，才应设置 `trusted_proxy_hops`。错误地信任
外部传入的转发头会允许攻击者伪造来源地址。公网部署应由反向代理终止 TLS，限制 API
监听地址，并只允许代理访问后端端口。

Token 的 `last_used_at` 默认最多每五分钟更新一次，避免每个只读请求都取得 SQLite 写锁。
该设置不会改变 Token 过期、禁用或权限校验行为。

内置 SOC 看板的 JavaScript 和 CSS 作为同源静态资源提供，不使用内联脚本或内联样式，
因此不需要放宽 CSP。访问令牌只存放在当前标签页的 `sessionStorage`，关闭标签页即清除；
生产环境仍应使用 TLS，避免令牌在传输链路中泄露。

除 `/health/*`、`/metrics` 和看板静态资源外，所有 `/api/v1` 接口至少要求 viewer 权限。
事件、告警、黑名单、主机、VPN 和 Worker 信息都不允许匿名读取。看板遇到 401 时会自动
提示输入访问令牌。

通用 Webhook 地址通过 `MONITOR_WEBHOOK_URL` 注入，签名密钥通过
`MONITOR_WEBHOOK_SECRET` 注入；企业微信使用 `MONITOR_WECHAT_WEBHOOK`。不要将带令牌的
Webhook URL 写入会提交到版本库的 YAML 文件。

所有 API 响应都会返回 `X-Request-ID`。客户端可以提供最多 128 个可打印 ASCII 字符的请求
标识；无效标识会由服务端重新生成。未捕获异常和就绪检查不会向客户端返回文件路径、数据库
错误或凭据等底层信息，完整堆栈只进入服务端日志。
