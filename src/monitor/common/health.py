def service_max_age(settings, service: str) -> int:
    """Use identical worker cadence thresholds in UI and release checks."""
    health = settings.section("health")
    base = max(1, int(health.get("heartbeat_max_age_seconds", 180)))
    matches = [(str(prefix), int(seconds))
               for prefix, seconds in (health.get("service_max_age_seconds", {}) or {}).items()
               if service.startswith(str(prefix))]
    return max(base, max(matches, key=lambda item: len(item[0]))[1]) if matches else base
