CREATE TABLE workspaces(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT 'single' CHECK(mode IN ('single','centralized','delegated')),
  region TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

INSERT INTO workspaces(id,name,description,mode,region,status,created_by,created_at,updated_at)
VALUES('default','默认安全运营空间','承接升级前已有数据和本地安全运营','single','local','active','system',datetime('now'),datetime('now'));

CREATE TABLE workspace_delegations(
  id TEXT PRIMARY KEY,
  source_workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  target_workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  delegation_type TEXT NOT NULL CHECK(delegation_type IN ('data','operation')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','revoked')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(source_workspace_id,target_workspace_id,delegation_type)
);

CREATE TABLE soc_assets(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  ip TEXT,
  hostname TEXT,
  site TEXT NOT NULL DEFAULT '',
  owner TEXT NOT NULL DEFAULT '',
  criticality TEXT NOT NULL DEFAULT 'medium' CHECK(criticality IN ('low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'unknown',
  source TEXT NOT NULL DEFAULT 'manual',
  attributes_json TEXT NOT NULL DEFAULT '{}',
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_soc_assets_workspace ON soc_assets(workspace_id,status,asset_type);
CREATE UNIQUE INDEX uq_soc_assets_workspace_ip ON soc_assets(workspace_id,ip) WHERE ip IS NOT NULL;

INSERT OR IGNORE INTO soc_assets(id,workspace_id,name,asset_type,ip,site,criticality,status,source,last_seen_at,created_at,updated_at)
SELECT 'host-' || replace(ip,'.','-'),'default',CASE WHEN name='' THEN ip ELSE name END,
       CASE kind WHEN 'vm' THEN 'virtual' ELSE kind END,ip,site,
       CASE kind WHEN 'site' THEN 'critical' WHEN 'physical' THEN 'high' ELSE 'medium' END,
       status,'host-monitor',last_checked_at,datetime('now'),datetime('now')
FROM hosts;

CREATE TRIGGER trg_host_soc_asset_insert AFTER INSERT ON hosts
BEGIN
  INSERT OR IGNORE INTO soc_assets(id,workspace_id,name,asset_type,ip,site,criticality,status,source,last_seen_at,created_at,updated_at)
  VALUES('host-' || replace(NEW.ip,'.','-'),'default',CASE WHEN NEW.name='' THEN NEW.ip ELSE NEW.name END,
         CASE NEW.kind WHEN 'vm' THEN 'virtual' ELSE NEW.kind END,NEW.ip,NEW.site,
         CASE NEW.kind WHEN 'site' THEN 'critical' WHEN 'physical' THEN 'high' ELSE 'medium' END,
         NEW.status,'host-monitor',NEW.last_checked_at,datetime('now'),datetime('now'));
END;

CREATE TRIGGER trg_host_soc_asset_update AFTER UPDATE OF name,status,last_checked_at,kind,site ON hosts
BEGIN
  UPDATE soc_assets SET name=CASE WHEN NEW.name='' THEN NEW.ip ELSE NEW.name END,
         asset_type=CASE NEW.kind WHEN 'vm' THEN 'virtual' ELSE NEW.kind END,
         site=NEW.site,status=NEW.status,last_seen_at=NEW.last_checked_at,updated_at=datetime('now')
  WHERE workspace_id='default' AND ip=NEW.ip AND source='host-monitor';
END;

CREATE TABLE vulnerabilities(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  asset_id TEXT REFERENCES soc_assets(id),
  cve TEXT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  cvss REAL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','accepted','remediated','false_positive')),
  remediation TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'manual',
  discovered_at TEXT NOT NULL,
  due_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_vulnerabilities_workspace ON vulnerabilities(workspace_id,status,severity);

CREATE TABLE baseline_findings(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  asset_id TEXT REFERENCES soc_assets(id),
  standard TEXT NOT NULL,
  control_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'failed' CHECK(status IN ('passed','failed','waived','unknown')),
  evidence TEXT NOT NULL DEFAULT '',
  recommendation TEXT NOT NULL DEFAULT '',
  checked_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_baselines_workspace ON baseline_findings(workspace_id,status,standard);

CREATE TABLE soc_alerts(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  event_id TEXT UNIQUE REFERENCES security_events(id),
  title TEXT NOT NULL,
  source TEXT NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','closed','suppressed')),
  mitre_tactic TEXT NOT NULL DEFAULT '',
  mitre_technique TEXT NOT NULL DEFAULT '',
  assignee TEXT,
  resolution TEXT,
  occurred_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_soc_alerts_workspace ON soc_alerts(workspace_id,status,severity,occurred_at);

CREATE TRIGGER trg_policy_decision_soc_alert AFTER INSERT ON policy_decisions
WHEN NEW.decision <> 'IGNORE'
BEGIN
  INSERT OR IGNORE INTO soc_alerts(id,workspace_id,event_id,title,source,src_ip,dst_ip,severity,status,
    mitre_tactic,mitre_technique,occurred_at,updated_at)
  SELECT 'alert-' || e.id,'default',e.id,e.category,e.source,e.src_ip,e.dst_ip,e.severity,'open',
    CASE
      WHEN lower(e.category) LIKE '%scan%' OR lower(e.category) LIKE '%probe%' THEN 'Discovery'
      WHEN lower(e.category) LIKE '%brute%' OR lower(e.category) LIKE '%login%' THEN 'Credential Access'
      WHEN lower(e.category) LIKE '%c2%' OR lower(e.category) LIKE '%trojan%' OR lower(e.category) LIKE '%botnet%' THEN 'Command and Control'
      WHEN lower(e.category) LIKE '%sql%' OR lower(e.category) LIKE '%rce%' OR lower(e.category) LIKE '%exploit%' THEN 'Initial Access'
      ELSE '' END,
    CASE
      WHEN lower(e.category) LIKE '%scan%' OR lower(e.category) LIKE '%probe%' THEN 'T1046'
      WHEN lower(e.category) LIKE '%brute%' OR lower(e.category) LIKE '%login%' THEN 'T1110'
      WHEN lower(e.category) LIKE '%c2%' OR lower(e.category) LIKE '%trojan%' OR lower(e.category) LIKE '%botnet%' THEN 'T1071'
      WHEN lower(e.category) LIKE '%sql%' OR lower(e.category) LIKE '%rce%' OR lower(e.category) LIKE '%exploit%' THEN 'T1190'
      ELSE '' END,
    e.occurred_at,NEW.created_at FROM security_events e WHERE e.id=NEW.event_id;
END;

INSERT OR IGNORE INTO soc_alerts(id,workspace_id,event_id,title,source,src_ip,dst_ip,severity,status,
  mitre_tactic,mitre_technique,occurred_at,updated_at)
SELECT 'alert-' || e.id,'default',e.id,e.category,e.source,e.src_ip,e.dst_ip,e.severity,'open',
  CASE
    WHEN lower(e.category) LIKE '%scan%' OR lower(e.category) LIKE '%probe%' THEN 'Discovery'
    WHEN lower(e.category) LIKE '%brute%' OR lower(e.category) LIKE '%login%' THEN 'Credential Access'
    WHEN lower(e.category) LIKE '%c2%' OR lower(e.category) LIKE '%trojan%' OR lower(e.category) LIKE '%botnet%' THEN 'Command and Control'
    WHEN lower(e.category) LIKE '%sql%' OR lower(e.category) LIKE '%rce%' OR lower(e.category) LIKE '%exploit%' THEN 'Initial Access'
    ELSE '' END,
  CASE
    WHEN lower(e.category) LIKE '%scan%' OR lower(e.category) LIKE '%probe%' THEN 'T1046'
    WHEN lower(e.category) LIKE '%brute%' OR lower(e.category) LIKE '%login%' THEN 'T1110'
    WHEN lower(e.category) LIKE '%c2%' OR lower(e.category) LIKE '%trojan%' OR lower(e.category) LIKE '%botnet%' THEN 'T1071'
    WHEN lower(e.category) LIKE '%sql%' OR lower(e.category) LIKE '%rce%' OR lower(e.category) LIKE '%exploit%' THEN 'T1190'
    ELSE '' END,
  e.occurred_at,e.received_at
FROM security_events e
WHERE EXISTS(SELECT 1 FROM policy_decisions d WHERE d.event_id=e.id AND d.decision<>'IGNORE')
ORDER BY e.occurred_at DESC LIMIT 5000;

CREATE TABLE threat_models(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'high',
  mitre_tactic TEXT NOT NULL DEFAULT '',
  mitre_technique TEXT NOT NULL DEFAULT '',
  query_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_threat_models_workspace ON threat_models(workspace_id,enabled);

CREATE TABLE operation_reports(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  report_type TEXT NOT NULL CHECK(report_type IN ('daily','weekly','monthly','custom')),
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  content_json TEXT NOT NULL,
  ai_analysis_id TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_reports_workspace ON operation_reports(workspace_id,created_at);

CREATE TABLE ai_analyses(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  analysis_type TEXT NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  status TEXT NOT NULL,
  input_summary_json TEXT NOT NULL,
  result_text TEXT,
  error TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE INDEX idx_ai_analyses_workspace ON ai_analyses(workspace_id,created_at);

CREATE TABLE platform_settings(
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  setting_key TEXT NOT NULL,
  setting_value TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(workspace_id,setting_key)
);

CREATE TABLE data_connectors(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  connector_type TEXT NOT NULL CHECK(connector_type IN ('syslog','api','logstash','kafka','webhook','file')),
  direction TEXT NOT NULL CHECK(direction IN ('ingest','delivery')),
  status TEXT NOT NULL DEFAULT 'disabled' CHECK(status IN ('disabled','observing','active','error')),
  config_json TEXT NOT NULL DEFAULT '{}',
  last_activity_at TEXT,
  last_error TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_data_connectors_workspace ON data_connectors(workspace_id,direction,status);

CREATE TABLE governance_frameworks(
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id,name,version)
);

INSERT INTO governance_frameworks(id,workspace_id,name,version,description,enabled,created_at,updated_at) VALUES
('gov-mlps-20','default','网络安全等级保护','2.0','等级保护通用安全要求检查框架',0,datetime('now'),datetime('now')),
('gov-iso-27001','default','ISO/IEC 27001','2022','信息安全管理体系检查框架',0,datetime('now'),datetime('now')),
('gov-pci-dss','default','PCI DSS','4.0','支付卡行业数据安全检查框架',0,datetime('now'),datetime('now')),
('gov-cis','default','CIS Controls','v8','互联网安全中心关键安全控制框架',0,datetime('now'),datetime('now'));

INSERT INTO threat_models(id,workspace_id,name,description,severity,mitre_tactic,mitre_technique,query_json,enabled,created_by,created_at,updated_at) VALUES
('tm-bruteforce','default','暴力破解检测','同一来源短时间内高频认证失败','high','Credential Access','T1110','{"category_regex":"brute|login failed|authentication failed","threshold":20,"window_seconds":300}',1,'system',datetime('now'),datetime('now')),
('tm-web-exploit','default','Web 攻击检测','聚合 SQL 注入、命令执行、文件上传等 Web 攻击','critical','Initial Access','T1190','{"category_regex":"sql|rce|webshell|upload|exploit","threshold":5,"window_seconds":300}',1,'system',datetime('now'),datetime('now')),
('tm-c2','default','C2 通信检测','识别木马、僵尸网络和命令控制通信','critical','Command and Control','T1071','{"category_regex":"c2|trojan|botnet|callback","threshold":1,"window_seconds":300}',1,'system',datetime('now'),datetime('now')),
('tm-scan','default','网络扫描检测','同一来源针对多个目标或端口的探测','medium','Discovery','T1046','{"category_regex":"scan|probe|recon","threshold":30,"window_seconds":300}',1,'system',datetime('now'),datetime('now'));
