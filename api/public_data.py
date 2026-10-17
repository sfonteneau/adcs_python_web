"""Read public X.509 certificates and redact configuration for the web API.

No modifications or additional methods are required in the upstream ADCS project.
All certificate data comes from AdcsTool's existing CA/certificate lookups.
"""
from __future__ import annotations

import base64
from pathlib import Path
import re
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


MAX_CERT_FILE = 2 * 1024 * 1024
PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
SECRET_FIELD_RE = re.compile(
    r"password|passwd|passphrase|pwd|secret|token|pin|credential|authorization|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|"
    r"client[_-]?secret|session[_-]?key|cookie|keytab|bearer|jwt",
    re.IGNORECASE,
)
INLINE_SECRET_RE = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----|"
    r"://[^\s/@]+:[^\s/@]+@|"
    r"(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|"
    r"access[_-]?key|client[_-]?secret|authorization|bearer|jwt|pin(?:[-_](?:value|source|file))?)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
REDACTED = "<masque>"


class CertificateContentError(Exception):
    """A public certificate cannot safely be returned through the API."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def redact_config(value: Any) -> Any:
    """Redact secret-bearing fields AND strings (including embedded URL passwords).

    This is a second protective layer over AdcsTool.show_config/show_ca.
    """
    if isinstance(value, dict):
        return {
            key: (REDACTED if SECRET_FIELD_RE.search(str(key)) or
                  str(key).lower() in {"key", "hmac", "auth_header"}
                  else redact_config(item))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_config(item) for item in value]
    if isinstance(value, str) and INLINE_SECRET_RE.search(value):
        return REDACTED
    return value


def read_public_certificate(tool: Any, ca_id: str, serial: str, fmt: str) -> dict:
    """Get PEM/DER or fullchain from the certificate selected by ADCS.

    Never accepts a user-supplied file path and never exposes a private key.
    The selected file must resolve within the selected CA's certificate store,
    and its first certificate must match the requested serial number.
    """
    if fmt not in {"pem", "der", "fullchain"}:
        raise CertificateContentError("Format invalide (pem, der ou fullchain)", 400)

    ca = tool.show_ca(ca_id)
    cert_dir = (ca.get("effective_storage_paths") or {}).get("cert_dir")
    details = tool.show_certificate(ca_id, serial)
    filename = details.get("file")
    if not isinstance(cert_dir, str) or not cert_dir or not isinstance(filename, str):
        raise CertificateContentError("Certificate path unavailable")
    if not Path(filename).is_absolute():
        raise CertificateContentError("Certificate path is not absolute")

    try:
        root = Path(cert_dir).resolve(strict=True)
        candidate = Path(filename).resolve(strict=True)
    except FileNotFoundError as exc:
        raise CertificateContentError("Certificate file not found", 404) from exc
    if not candidate.is_relative_to(root) or candidate == root or not candidate.is_file():
        raise CertificateContentError("Certificat hors du stockage de cette CA", 403)

    with candidate.open("rb") as stream:
        content = stream.read(MAX_CERT_FILE + 1)
    if len(content) > MAX_CERT_FILE:
        raise CertificateContentError("Certificate file too large", 413)

    try:
        blocks = PEM_CERT_RE.findall(content)
        if blocks:
            if len(blocks) > 20:
                raise CertificateContentError("Chaine de certificats trop longue")
            certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
        else:
            certificates = [x509.load_der_x509_certificate(content)]
    except ValueError as exc:
        raise CertificateContentError("Fichier X.509 invalide ou format non pris en charge") from exc

    leaf = certificates[0]
    if leaf.serial_number != int(serial, 16):
        raise CertificateContentError("Le numero de serie du fichier ne correspond pas", 409)

    serial_label = f"{leaf.serial_number:X}"
    if fmt == "der":
        raw = leaf.public_bytes(Encoding.DER)
        return {"serial": serial_label, "format": fmt, "encoding": "base64",
                "content": base64.b64encode(raw).decode("ascii"),
                "filename": serial_label + ".cer", "mime_type": "application/pkix-cert"}

    if fmt == "fullchain":
        raw = b"".join(cert.public_bytes(Encoding.PEM) for cert in certificates)
        suffix = ".fullchain.pem"
    else:
        raw = leaf.public_bytes(Encoding.PEM)
        suffix = ".crt.pem"
    return {"serial": serial_label, "format": fmt, "encoding": "utf-8",
            "content": raw.decode("ascii"), "filename": serial_label + suffix,
            "mime_type": "application/x-pem-file"}
