from .base import BaseParser
from .detector import LogFormat
from .json_lines import JsonLinesParser
from .nginx import NginxCombinedParser
from .plaintext import PlaintextParser
from .syslog import AuthLogParser, SyslogParser


def get_parser(fmt: LogFormat, source: str) -> BaseParser:
    match fmt:
        case LogFormat.JSON_LINES:
            return JsonLinesParser(source)
        case LogFormat.NGINX_COMBINED:
            return NginxCombinedParser(source)
        case LogFormat.SYSLOG:
            return SyslogParser(source)
        case LogFormat.AUTH_LOG:
            return AuthLogParser(source)
        case LogFormat.EVTX:
            return _evtx_parser(source)
        case _:
            return PlaintextParser(source)


def _evtx_parser(source: str) -> BaseParser:
    try:
        from .evtx import EvtxParser

        return EvtxParser(source)
    except ImportError:
        raise RuntimeError("python-evtx not installed. Run: pip install logsense[evtx]")
