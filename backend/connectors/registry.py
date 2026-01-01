from typing import Dict, Type
from connectors.base import BaseSIEMConnector, ConnectorConfig

class ConnectorRegistry:
    _registry: Dict[str, Type[BaseSIEMConnector]] = {}
    _instances: Dict[str, BaseSIEMConnector] = {}

    @classmethod
    def register(cls, platform_name: str):
        """Decorator to register a connector class for a platform."""
        def decorator(connector_cls: Type[BaseSIEMConnector]):
            cls._registry[platform_name] = connector_cls
            return connector_cls
        return decorator

    @classmethod
    def get_connector_class(cls, platform_name: str) -> Type[BaseSIEMConnector]:
        return cls._registry.get(platform_name)

    @classmethod
    def get_connector(cls, platform_name: str, config: ConnectorConfig) -> BaseSIEMConnector:
        """Get or create singleton instance of connector"""
        # In a real app, config might change, so singleton might be tricky.
        # But for webhook receivers usually config is static per deployment.
        if platform_name not in cls._instances:
            connector_cls = cls.get_connector_class(platform_name)
            if not connector_cls:
                raise ValueError(f"No connector registered for platform '{platform_name}'")
            cls._instances[platform_name] = connector_cls(config)
        return cls._instances[platform_name]

    @classmethod
    def list_platforms(cls):
        return list(cls._registry.keys())
