class MonitorError(Exception):
    """Base application error."""


class ConfigError(MonitorError):
    pass


class ParseError(MonitorError):
    pass


class IgnoredLog(MonitorError):
    """A valid source log that did not satisfy local security detection rules."""


class ExternalServiceError(MonitorError):
    pass
