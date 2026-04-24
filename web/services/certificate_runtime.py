"""Compatibility shim for proxy/runtime imports.

The canonical certificate implementation lives in `services.certificate_core`.
Keep this module as a thin re-export layer for any callers that still import
the older runtime-oriented path.
"""

from services.certificate_core import CertificateBundle, CertManager, build_certificate_bundle, load_local_certificate_bundle, materialize_certificate_bundle

__all__ = [
    "CertificateBundle",
    "CertManager",
    "build_certificate_bundle",
    "load_local_certificate_bundle",
    "materialize_certificate_bundle",
]
