"""
ConfigScore Scanner Package
Modular passive website security assessment engine.
"""

from .engine import scan_website
from .report import generate_pdf_report

__all__ = ["scan_website", "generate_pdf_report"]
