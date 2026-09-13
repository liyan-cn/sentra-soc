from __future__ import annotations

import ipaddress


def find_whitelist_match(conn, ip: str, now_iso: str):
    address = ipaddress.ip_address(ip)
    rows = conn.execute(
        """SELECT id,network,reason,expires_at FROM whitelist_entries
        WHERE enabled=1 AND (expires_at IS NULL OR expires_at>?)""", (now_iso,)
    ).fetchall()
    best = None
    best_prefix = -1
    for row in rows:
        try:
            network = ipaddress.ip_network(row["network"], strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network and network.prefixlen > best_prefix:
            best, best_prefix = row, network.prefixlen
    return best

