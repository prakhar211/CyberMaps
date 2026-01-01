"""Connectors package initialization"""

from connectors.base import BaseSIEMConnector, ConnectorConfig
from connectors.coralogix_connector import CoralogixConnector
from connectors.field_mapper import FieldMapper

__all__ = [
    "BaseSIEMConnector",
    "ConnectorConfig",
    "CoralogixConnector",
    "FieldMapper",
]
