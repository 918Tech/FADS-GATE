"""FADS-GATE defensive agent capability gateway."""

from .gateway import CapabilityGateway, GatewayResult
from .guardian import DetectionReport, FADSGuardian
from .policy import CapabilityPolicy, PolicyRule

__all__ = [
    "CapabilityGateway",
    "CapabilityPolicy",
    "DetectionReport",
    "FADSGuardian",
    "GatewayResult",
    "PolicyRule",
]

__version__ = "0.1.0"
