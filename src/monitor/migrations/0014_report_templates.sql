CREATE TABLE IF NOT EXISTS report_templates(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  report_type TEXT NOT NULL CHECK(report_type IN ('daily','weekly','monthly','custom')),
  sections_json TEXT NOT NULL DEFAULT '[]',
  is_default INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id,name)
);
INSERT OR IGNORE INTO report_templates
 (id,workspace_id,name,description,report_type,sections_json,is_default,created_by,created_at,updated_at)
 VALUES
 ('tpl-default-daily','default','SOC 交接日报','态势摘要、告警处置、数据健康和下一班次关注项','daily',
  '["态势摘要","新增与处置告警","高风险来源与威胁 TOP10","资产与采集健康","下一班次关注项"]',1,'system',datetime('now'),datetime('now')),
 ('tpl-default-weekly','default','威胁运营周报','检测质量、MITRE 覆盖、剧本回放和改进建议','weekly',
  '["本周安全态势","威胁类型与来源趋势","MITRE ATT&CK 覆盖","剧本执行与人工研判","风险改进计划"]',1,'system',datetime('now'),datetime('now')),
 ('tpl-default-monthly','default','管理层安全风险月报','暴露面、处置效率、治理状态和决策事项','monthly',
  '["管理摘要","重大风险与暴露面","告警处置效率","资产/基线/漏洞治理","下月重点决策"]',1,'system',datetime('now'),datetime('now'));
