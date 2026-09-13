CREATE TABLE asset_network_inventory(
  ip TEXT PRIMARY KEY,
  mac_address TEXT NOT NULL DEFAULT '',
  physical_host_ip TEXT NOT NULL DEFAULT '',
  vlan TEXT NOT NULL DEFAULT '',
  interface TEXT NOT NULL DEFAULT '',
  arp_type TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  observed_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_asset_network_inventory_mac ON asset_network_inventory(mac_address);

CREATE TRIGGER trg_asset_network_inventory_attach AFTER INSERT ON soc_assets
WHEN NEW.ip IS NOT NULL AND EXISTS(SELECT 1 FROM asset_network_inventory WHERE ip=NEW.ip)
BEGIN
  UPDATE soc_assets SET attributes_json=json_set(
    CASE WHEN json_valid(attributes_json) THEN attributes_json ELSE '{}' END,
    '$.mac_address',(SELECT mac_address FROM asset_network_inventory WHERE ip=NEW.ip),
    '$.physical_host_ip',(SELECT physical_host_ip FROM asset_network_inventory WHERE ip=NEW.ip),
    '$.network_inventory_source',(SELECT source FROM asset_network_inventory WHERE ip=NEW.ip)
  ) WHERE id=NEW.id;
END;
