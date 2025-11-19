"""
Modules d'analyse SPF et DMARC
"""

from .spf_analyzer import SPFAnalyzer, SPFRecord, SPFAnalysisResult
from .dmarc_analyzer import analyze_dmarc_security, get_dmarc_record

__all__ = [
    'SPFAnalyzer',
    'SPFRecord',
    'SPFAnalysisResult',
    'analyze_dmarc_security',
    'get_dmarc_record'
]
