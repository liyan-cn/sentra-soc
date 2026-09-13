from __future__ import annotations

from datetime import datetime, timezone, timedelta
import re

LOCAL_TIMEZONE = timezone(timedelta(hours=8), 'Asia/Shanghai')


def syslog_time(line: str, reference: datetime | None = None) -> datetime:
    reference = reference or datetime.now(timezone.utc)
    # An explicit RFC3339 zone is authoritative; never apply another +8 hours.
    prefix = re.match(r'^(?:<\d+>\d?\s*)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))', line)
    if prefix:
        return datetime.fromisoformat(prefix[1].replace('Z','+00:00')).astimezone(timezone.utc)
    line = re.sub(r'^<\d+>', '', line)
    candidates = (
        (line[:20].strip(), "%b %d %H:%M:%S %Y"),
        (line[:15].strip(), "%b %d %H:%M:%S"),
    )
    for value, fmt in candidates:
        try:
            result = datetime.strptime(value, fmt)
            if fmt == "%b %d %H:%M:%S":
                year = reference.astimezone(LOCAL_TIMEZONE).year
                # RFC3164 omits its year; allow a December log received in January.
                if result.month == 12 and reference.astimezone(LOCAL_TIMEZONE).month == 1:
                    year -= 1
                return result.replace(year=year, tzinfo=LOCAL_TIMEZONE).astimezone(timezone.utc)
            return result.replace(tzinfo=LOCAL_TIMEZONE).astimezone(timezone.utc)
        except ValueError:
            continue
    return reference.astimezone(timezone.utc)
