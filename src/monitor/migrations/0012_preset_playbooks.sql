WITH presets(n,name,pattern) AS (VALUES
  (1,'健康检查告警关闭','health.?check|健康检查'),
  (2,'负载均衡探活关闭','load.?balancer|探活'),
  (3,'监控平台探测关闭','monitoring|监控探测'),
  (4,'WAF 自检事件关闭','self.?test|自检'),
  (5,'授权漏洞扫描观察','authorized.?scan|授权扫描'),
  (6,'资产测绘任务观察','asset.?survey|资产测绘'),
  (7,'备份系统连接检查','backup.?probe|备份检查'),
  (8,'DNS 可用性探测','dns.?monitor|DNS探测'),
  (9,'CDN 回源探测','cdn|回源探测'),
  (10,'静态资源安全扫描','static.?resource|静态资源'),
  (11,'业务拨测告警关闭','synthetic|业务拨测'),
  (12,'运维堡垒机检查','bastion|堡垒机检查'),
  (13,'配置中心健康检查','config.?center|配置中心'),
  (14,'API 网关探活','api.?gateway|网关探活'),
  (15,'容器健康检查','kubernetes|k8s|容器探活'),
  (16,'数据库连接池探活','database.?health|数据库探活'),
  (17,'消息队列健康检查','kafka|rabbitmq|消息队列探活'),
  (18,'缓存服务健康检查','redis.?health|缓存探活'),
  (19,'邮件网关探活','mail.?gateway|邮件探活'),
  (20,'VPN 网关健康检查','vpn.?health|VPN探活'),
  (21,'防病毒更新连接','antivirus.?update|病毒库更新'),
  (22,'补丁平台连接检查','patch.?service|补丁检查'),
  (23,'时间同步探测','ntp|时间同步'),
  (24,'证书状态探测','certificate.?check|证书检查'),
  (25,'链路监控探测','link.?monitor|链路探测'),
  (26,'日志平台回环测试','syslog.?test|日志测试'),
  (27,'可信爬虫观察','trusted.?crawler|可信爬虫'),
  (28,'应用发布验证','deployment.?verify|发布验证'),
  (29,'灾备切换演练','dr.?drill|灾备演练'),
  (30,'维护窗口低风险关闭','maintenance.?window|维护窗口')
)
INSERT OR IGNORE INTO managed_playbooks(id,name,enabled,priority,definition_json,version,created_by,updated_by,created_at,updated_at)
SELECT printf('preset-%02d',n),name,0,100-n,
       '{"id":"' || printf('preset-%02d',n) || '","name":"' || name ||
       '","enabled":false,"priority":' || (100-n) ||
       ',"trigger":"review_created","match":{"decision":"MANUAL_REVIEW","category_regex":"' || pattern ||
       '","severity":["low","medium"],"count_lte":20},"actions":[{"type":"close_review","reason":"预置模板命中；启用前必须完成历史回放与观察期验证"}]}' ,
       1,'system','system',datetime('now'),datetime('now')
FROM presets;
