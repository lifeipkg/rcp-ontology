"""rcp-ontology：平台本体（TBox）与一致性检查器。"""

from .loader import Finding, LoadError, load_concepts, load_registry

__all__ = ["Finding", "LoadError", "load_concepts", "load_registry"]
__version__ = "1.0.0"
