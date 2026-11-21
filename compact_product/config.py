from dataclasses import dataclass, asdict
import json
from pathlib import Path
import re
from compact_behavior.source import settings, ElasticWindow
from compact_behavior import FIVE


@dataclass(frozen=True)
class Config:
    source_schema: str = "p24_compact_v2"
    ad_schema: str = "p24_compact_ad_v2"
    host: str = "0.0.0.0"
    web_ports: tuple = (5021, 5022)
    reference_windows: int = 24
    overlap_windows: int = 2
    recheck_seconds: int = 300
    ingest_budget_seconds: int = 180
    source_lag_seconds: int = 60
    idle_seconds: int = 2

    def validate(self):
        if not re.fullmatch(r"p24_compact_[a-z0-9_]{1,32}", self.source_schema):
            raise ValueError("new_compact_namespace_required")
        if not re.fullmatch(r"p24_compact_ad_[a-z0-9_]{1,32}", self.ad_schema):
            raise ValueError("new_compact_ad_namespace_required")
        if not 12 <= self.reference_windows <= 288:
            raise ValueError("reference_windows_12_to_288")
        if not 0 <= self.overlap_windows <= 6:
            raise ValueError("overlap_windows_0_to_6")
        if not 60 <= self.recheck_seconds <= 3600:
            raise ValueError("recheck_seconds_60_to_3600")
        if (
            not 15 <= self.ingest_budget_seconds <= 600
            or not 1 <= self.idle_seconds <= 15
        ):
            raise ValueError("invalid_worker_budget")
        if not 30 <= self.source_lag_seconds <= 600:
            raise ValueError("invalid_source_lag")
        if (
            not self.web_ports
            or len(self.web_ports) > 2
            or any(type(p) != int or not 1024 <= p <= 65535 for p in self.web_ports)
        ):
            raise ValueError("invalid_web_ports")
        if len(set(self.web_ports)) != len(self.web_ports):
            raise ValueError("duplicate_web_port")
        import ipaddress

        ipaddress.ip_address(self.host)
        return self


def load(project):
    project = Path(project).resolve()
    path = project / "compact_product.local.json"
    values = json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else {}
    if "web_ports" in values:
        values["web_ports"] = tuple(values["web_ports"])
    config = Config(**values).validate()
    source = settings(project / "viewer_config.local.py")
    if not isinstance(source.get("ELASTICSEARCH"), dict):
        raise ValueError("literal_ELASTICSEARCH_required")
    stream = ElasticWindow(source["ELASTICSEARCH"], 0, FIVE).namespace
    return config, source, stream
