"""Authenticated JSON-only API wrapping the UNMODIFIED ADCS CLI Python API.

Start with: python -m api.server
Or production: waitress-serve --listen=127.0.0.1:8001 api.wsgi:app
Python 3.9+ on Linux.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import logging
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable

from flask import Flask, g, jsonify, request, send_file
from werkzeug.exceptions import HTTPException

from .auth import SessionStore, check_password
from .locks import operation_lock
from .public_data import CertificateContentError, read_public_certificate, redact_config

LOG = logging.getLogger(__name__)
SERIAL_RE = re.compile(r"(?:0[xX])?[0-9a-fA-F]{1,128}\Z")
ACTIONS = ("revoke", "unrevoke", "delete")
STATUSES = ("any", "expired", "expiring", "valid")
REVOCATIONS = ("any", "revoked", "not_revoked")
# Public whitelist of adcs_cert_store.parse_order_by fields. Keep API parsing
# independent of the original source: only AdcsTool is imported at runtime.
SORT_FIELDS = frozenset((
    "subject", "not_before", "not_after", "days", "serial", "revoked",
    "filename", "signature", "public_key", "sha256", "is_ca",
    "days_to_expiry", "expiration_date", "expires", "valid_until",
    "issued", "issue_date", "file", "serial_number", "fingerprint",
))
SORT_TERM_RE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\s+(?:ASC|DESC))?\Z", re.I)


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "invalid_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


@dataclass(frozen=True)
class Settings:
    project_path: str
    config_path: str
    username: str
    password_hash: str
    session_db: str
    lock_dir: str
    allowed_origins: frozenset[str]
    token_ttl: int = 3600

    @classmethod
    def from_env(cls) -> "Settings":
        root = Path(__file__).resolve().parent.parent
        project = os.environ.get("ADCS_PROJECT_PATH", "").strip()
        password_hash = os.environ.get("ADCS_WEB_PASSWORD_HASH", "").strip()
        user = os.environ.get("ADCS_WEB_USERNAME", "admin").strip()
        if not project or not Path(project, "adcs_tool.py").is_file():
            raise RuntimeError("Set ADCS_PROJECT_PATH to the directory containing the existing adcs_tool.py")
        if not password_hash.startswith("pbkdf2_sha256$"):
            raise RuntimeError("Set ADCS_WEB_PASSWORD_HASH (generate with python -m api.auth hash-password)")
        if not user:
            raise RuntimeError("ADCS_WEB_USERNAME cannot be empty")
        origins = os.environ.get("ADCS_WEB_ALLOWED_ORIGINS", "http://127.0.0.1:8080,http://localhost:8080")
        allowed = frozenset(origin.strip().rstrip("/") for origin in origins.split(",") if origin.strip())
        ttl = int(os.environ.get("ADCS_WEB_TOKEN_TTL", "3600"))
        if not 300 <= ttl <= 86400:
            raise RuntimeError("ADCS_WEB_TOKEN_TTL must be 300-86400 seconds")
        state = root / ".state"
        return cls(project_path=os.path.abspath(project),
                   config_path=os.environ.get("ADCS_CONFIG_PATH", "/etc/adcs/adcs.yaml"),
                   username=user, password_hash=password_hash,
                   session_db=os.environ.get("ADCS_WEB_SESSION_DB", str(state / "sessions.sqlite3")),
                   lock_dir=os.environ.get("ADCS_WEB_LOCK_DIR", str(state / "locks")),
                   allowed_origins=allowed, token_ttl=ttl)


def json_data(value: Any, status: int = 200):
    return jsonify({"data": value}), status


def body_json() -> dict:
    if not request.is_json:
        raise ApiError("Content-Type must be application/json", 415, "unsupported_media_type")
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ApiError("Expected a JSON object")
    return payload


def only(data: dict, *allowed: str):
    unexpected = set(data) - set(allowed)
    if unexpected:
        raise ApiError("Unknown field(s): " + ", ".join(sorted(unexpected)))


def text_field(data: dict, key: str, default=None, *, required=False, max_length=255) -> str | None:
    value = data.get(key, default)
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > max_length:
        raise ApiError("Invalid " + key)
    return value.strip()


def int_field(data: dict, key: str, default: int | None, *, minimum=0, maximum=1_000_000) -> int | None:
    value = data.get(key, default)
    if value is None:
        return None
    if type(value) is not int or value < minimum or value > maximum:
        raise ApiError("Invalid " + key)
    return value


def bool_field(data: dict, key: str, default: bool = False) -> bool:
    value = data.get(key, default)
    if type(value) is not bool:
        raise ApiError("Invalid " + key)
    return value


def serial_field(serial: str) -> str:
    if not isinstance(serial, str) or not SERIAL_RE.fullmatch(serial):
        raise ApiError("Serial must be hexadecimal")
    return serial


def serials_field(data: dict) -> list[str]:
    serials = data.get("serials")
    if not isinstance(serials, list) or not 1 <= len(serials) <= 5000:
        raise ApiError("serials must contain 1 to 5000 hexadecimal serials")
    values = [serial_field(item) for item in serials]
    # Preserve order but avoid duplicate actions. Treat 0x prefix and leading zeroes as equivalent.
    return list({int(value, 16): value for value in reversed(values)}.values())[::-1]


def order_by_field(value: str) -> str:
    parts = [part.strip() for part in value.split(",")]
    if not parts or len(parts) > 8:
        raise ApiError("Invalid order_by")
    for part in parts:
        if not SORT_TERM_RE.fullmatch(part) or part.split()[0].lower() not in SORT_FIELDS:
            raise ApiError("Invalid order_by")
    return value


def filter_fields(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ApiError("filter must be an object")
    only(data, "status", "revocation", "search", "order_by", "limit", "eligible")
    status = text_field(data, "status", "any", max_length=30)
    revocation = text_field(data, "revocation", "any", max_length=30)
    if status not in STATUSES or revocation not in REVOCATIONS:
        raise ApiError("Invalid filter status or revocation")
    return {"status": status, "revocation": revocation,
            "search": text_field(data, "search", "", max_length=256),
            "order_by": order_by_field(text_field(data, "order_by", "not_after ASC", max_length=200)),
            "limit": int_field(data, "limit", 0, maximum=50_000),
            "eligible": bool_field(data, "eligible", False)}


def create_app(*, settings: Settings | None = None,
               tool_factory: Callable[[], Any] | None = None) -> Flask:
    """Dependency injection is used by tests; normal mode imports upstream adcs_tool."""
    settings = settings or Settings.from_env()
    if tool_factory is None:
        # Import, don't copy, shell out to, or patch the original ADCS project.
        if settings.project_path not in sys.path:
            sys.path.insert(0, settings.project_path)
        from adcs_tool import AdcsTool
        tool_factory = lambda: AdcsTool(settings.config_path)

    sessions = SessionStore(settings.session_db, settings.token_ttl)
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
    app.config["JSON_SORT_KEYS"] = False
    app.json.ensure_ascii = False
    app.extensions["adcs_sessions"] = sessions
    # Documentation contains only the public API contract (no CA config/secrets).
    # The operational routes all retain their existing Bearer authentication.
    PUBLIC_ENDPOINTS = {"health", "login", "docs", "docs_loader", "docs_style", "docs_asset", "openapi"}
    docs_dir = Path(__file__).resolve().parent / "docs"
    spec_file = Path(__file__).resolve().parent / "openapi.json"

    def tool():
        if "adcs_tool" not in g:
            g.adcs_tool = tool_factory()
        return g.adcs_tool

    def locked(scope, callback):
        # Every mutation is serialized across API workers, including resign-all,
        # so two different web actions cannot rewrite the same CRL concurrently.
        with operation_lock(settings.lock_dir, "global-mutations"):
            with operation_lock(settings.lock_dir, scope):
                return callback()

    @app.before_request
    def authenticate():
        if request.method == "OPTIONS":
            return "", 204
        if request.endpoint in PUBLIC_ENDPOINTS:
            return
        value = request.headers.get("Authorization", "")
        kind, sep, token = value.partition(" ")
        if not sep or kind.lower() != "bearer" or not token:
            raise ApiError("Bearer token required", 401, "unauthorized")
        session = sessions.lookup(token)
        if not session:
            raise ApiError("Session expired or invalid", 401, "unauthorized")
        g.user = session["username"]
        g.token = token
        g.expires_at = session["expires_at"]

    @app.after_request
    def secure_headers(response):
        origin = request.headers.get("Origin")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Max-Age"] = "600"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.path.startswith("/api/docs"):
            # Swagger may fall back to pinned CDN assets until they are vendored.
            # Prefer `python scripts/vendor_swagger_ui.py` for production.
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; script-src 'self' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data:; font-src 'self' data: https://cdn.jsdelivr.net; "
                "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
            )
            response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.errorhandler(Exception)
    def handle_error(error):
        if isinstance(error, ApiError):
            status, code, message = error.status, error.code, error.message
        elif isinstance(error, HTTPException):
            status, code, message = error.code or 500, "http_error", error.description
        elif isinstance(error, LookupError):
            status, code, message = 404, "not_found", str(error)
        elif isinstance(error, ValueError):
            status, code, message = 400, "invalid_request", str(error)
        elif isinstance(error, PermissionError):
            LOG.exception("ADCS filesystem permission denied")
            status, code, message = 403, "filesystem_permission", "ADCS file permissions denied"
        else:
            LOG.exception("ADCS API operation failed")
            status, code, message = 500, "internal_error", "Internal API error; see server logs"
        return jsonify({"error": {"code": code, "message": message}}), status

    @app.get("/api/openapi.json", endpoint="openapi")
    def openapi_spec():
        # Read a standalone, versioned JSON document; no ADCS config is loaded.
        with spec_file.open("r", encoding="utf-8") as fh:
            return jsonify(json.load(fh))

    @app.get("/api/docs", endpoint="docs")
    @app.get("/api/docs/", endpoint="docs")
    def docs():
        return send_file(docs_dir / "index.html", mimetype="text/html")

    @app.get("/api/docs/loader.js", endpoint="docs_loader")
    def docs_loader():
        return send_file(docs_dir / "loader.js", mimetype="application/javascript")

    @app.get("/api/docs/style.css", endpoint="docs_style")
    def docs_style():
        return send_file(docs_dir / "style.css", mimetype="text/css")

    @app.get("/api/docs/assets/<filename>", endpoint="docs_asset")
    def docs_asset(filename):
        # Vendored Swagger UI assets, if installed. Strict allowlist; no path access.
        types = {"swagger-ui.css": "text/css", "swagger-ui-bundle.js": "application/javascript"}
        if filename not in types:
            raise ApiError("Unknown documentation asset", 404, "not_found")
        candidate = docs_dir / "assets" / filename
        if not candidate.is_file():
            raise ApiError("Swagger asset not vendored", 404, "not_found")
        return send_file(candidate, mimetype=types[filename])

    @app.get("/api/v1/health", endpoint="health")
    def health():
        return json_data({"status": "ok"})

    @app.post("/api/v1/auth/login", endpoint="login")
    def login():
        payload = body_json()
        only(payload, "username", "password")
        username = text_field(payload, "username", "", max_length=100)
        password = payload.get("password")
        if not isinstance(password, str) or len(password) > 4096:
            raise ApiError("Invalid login", 401, "invalid_credentials")
        ip = (request.remote_addr or "unknown")[:128]
        if sessions.locked(ip):
            raise ApiError("Too many attempts; try again in 5 minutes", 429, "rate_limited")
        # Always check password (even with wrong username) to avoid user enumeration timing.
        good_password = check_password(password, settings.password_hash)
        if not good_password or username != settings.username:
            sessions.note_failure(ip)
            raise ApiError("Invalid login", 401, "invalid_credentials")
        sessions.clear_failures(ip)
        token = sessions.issue(username)
        return json_data({"access_token": token, "token_type": "Bearer",
                          "expires_in": settings.token_ttl, "username": username})

    @app.get("/api/v1/capabilities")
    def capabilities():
        return json_data({
            "api_version": "v1",
            "features": ["ca-list", "ca-show", "ca-create", "certificate-list",
                         "certificate-show", "certificate-download", "certificate-issue", "certificate-revoke",
                         "certificate-unrevoke", "certificate-delete", "crl-resign",
                         "crl-resign-all", "ket-create", "csr-submit", "certificate-rotate",
                         "callback-list", "config-show"],
            "max_serials_per_action": 5000,
        })

    @app.get("/api/v1/auth/me")
    def me():
        return json_data({"username": g.user, "expires_at": g.expires_at})

    @app.post("/api/v1/auth/logout")
    def logout():
        sessions.revoke(g.token)
        return json_data({"logged_out": True})

    @app.get("/api/v1/cas")
    def ca_list():
        return json_data(tool().list_cas())

    @app.get("/api/v1/cas/<ca_id>")
    def ca_show(ca_id):
        return json_data(redact_config(tool().show_ca(ca_id)))

    @app.post("/api/v1/cas")
    def ca_create():
        p = body_json()
        only(p, "cn", "aia_crl_base_url", "signer_ca_id", "csr_path", "crt_path",
             "key_path", "crl_path", "rsa_bits", "key_type", "ec_curve", "mldsa_variant",
             "valid_days", "confirm")
        if not bool_field(p, "confirm"):
            raise ApiError("Creation requires confirm=true")
        args = {"cn": text_field(p, "cn", required=True),
                "aia_crl_base_url": text_field(p, "aia_crl_base_url", required=True, max_length=2048),
                "signer_ca_id": text_field(p, "signer_ca_id"),
                "csr_path": text_field(p, "csr_path", max_length=2048),
                "crt_path": text_field(p, "crt_path", max_length=2048),
                "key_path": text_field(p, "key_path", max_length=2048),
                "crl_path": text_field(p, "crl_path", max_length=2048),
                "rsa_bits": int_field(p, "rsa_bits", 4096, minimum=2048, maximum=16384),
                "key_type": text_field(p, "key_type", "rsa"),
                "ec_curve": text_field(p, "ec_curve", "secp256r1"),
                "mldsa_variant": text_field(p, "mldsa_variant", "mldsa65"),
                "valid_days": int_field(p, "valid_days", 3650, minimum=1, maximum=365000)}
        return json_data(locked("global-config", lambda: tool().create_ca(**args)), 201)

    @app.get("/api/v1/cas/<ca_id>/certificates")
    def certificates(ca_id):
        if any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ApiError("Query parameters must not be repeated")
        q = dict(request.args)
        only(q, "status", "revocation", "search", "order_by", "limit")
        if "limit" in q:
            if not re.fullmatch(r"[0-9]{1,5}", q["limit"]):
                raise ApiError("Invalid limit")
            q["limit"] = int(q["limit"])
        opts = filter_fields(q)
        return json_data(tool().list_certificates(
            ca_id, status=opts["status"], revocation=opts["revocation"],
            search=opts["search"], order_by=opts["order_by"], limit=opts["limit"]))

    @app.get("/api/v1/cas/<ca_id>/certificates/<serial>")
    def certificate_show(ca_id, serial):
        return json_data(tool().show_certificate(ca_id, serial_field(serial)))

    @app.get("/api/v1/cas/<ca_id>/certificates/<serial>/content")
    def certificate_content(ca_id, serial):
        if any(len(request.args.getlist(key)) != 1 for key in request.args):
            raise ApiError("Query parameters must not be repeated")
        options = dict(request.args)
        only(options, "format")
        fmt = options.get("format", "pem")
        try:
            result = read_public_certificate(tool(), ca_id, serial_field(serial), fmt)
        except CertificateContentError as exc:
            raise ApiError(str(exc), exc.status, "certificate_unavailable") from exc
        return json_data(result)

    @app.post("/api/v1/cas/<ca_id>/certificates")
    def certificate_issue(ca_id):
        p = body_json()
        only(p, "cn", "sans", "crt_path", "key_path", "rsa_bits", "valid_days", "confirm")
        if not bool_field(p, "confirm"):
            raise ApiError("Issuing a certificate requires confirm=true")
        sans = p.get("sans", [])
        if not isinstance(sans, list) or len(sans) > 100 or any(
                not isinstance(s, str) or not s or len(s) > 255 for s in sans):
            raise ApiError("sans must be a list of up to 100 names")
        args = {"cn": text_field(p, "cn", required=True), "sans": sans,
                "crt_path": text_field(p, "crt_path", max_length=2048),
                "key_path": text_field(p, "key_path", max_length=2048),
                "rsa_bits": int_field(p, "rsa_bits", 3072, minimum=2048, maximum=16384),
                "valid_days": int_field(p, "valid_days", 365, minimum=1, maximum=365000)}
        return json_data(locked("ca:" + ca_id, lambda: tool().issue_certificate(ca_id, **args)), 201)

    @app.post("/api/v1/cas/<ca_id>/certificates/actions/<action>")
    def certificate_action(ca_id, action):
        if action not in ACTIONS:
            raise ApiError("Unknown certificate action", 404, "not_found")
        p = body_json()
        only(p, "serials", "filter", "dry_run", "confirm", "next_update_hours")
        if ("serials" in p) == ("filter" in p):
            raise ApiError("Provide either serials or filter, not both")
        dry_run = bool_field(p, "dry_run")
        if not dry_run and not bool_field(p, "confirm"):
            raise ApiError("This operation requires confirm=true")
        hours = int_field(p, "next_update_hours", None, minimum=1, maximum=8760)
        if action == "delete" and hours is not None:
            raise ApiError("next_update_hours not applicable to deletion")

        def execute():
            if "serials" in p:
                serials = serials_field(p)
                if action != "delete":
                    method = tool().revoke_certificate if action == "revoke" else tool().unrevoke_certificate
                    # One single API call for the entire selection, i.e. one CRL update.
                    return method(ca_id, serials, dry_run=dry_run, next_update_hours=hours)
                # Upstream supports bulk deletion by filter, but individual serial deletion
                # only: preserve its eligibility checks and collect per-serial failures.
                results, errors = [], []
                for serial in serials:
                    try:
                        results.append(tool().delete_certificate(ca_id, serial, dry_run=dry_run))
                    except (ValueError, LookupError, OSError) as exc:
                        errors.append({"serial": serial, "error": str(exc)})
                return {"action": "delete", "ca": ca_id, "dry_run": dry_run,
                        "total": len(serials), "selected": len(serials), "successes": 0 if dry_run else len(results),
                        "failures": len(errors), "results": results, "errors": errors}
            opts = filter_fields(p["filter"])
            if action == "delete":
                return tool().delete_certificates(
                    ca_id, eligible=opts["eligible"], status=opts["status"],
                    revocation=opts["revocation"], search=opts["search"],
                    order_by=opts["order_by"], limit=opts["limit"],
                    apply=not dry_run)
            if opts["eligible"]:
                raise ApiError("eligible filter is only valid for deletion")
            method = tool().revoke_certificates if action == "revoke" else tool().unrevoke_certificates
            return method(ca_id, status=opts["status"], revocation=opts["revocation"],
                          search=opts["search"], order_by=opts["order_by"], limit=opts["limit"],
                          apply=not dry_run, next_update_hours=hours)

        # Even previews are serialized to prevent races with other web actions.
        return json_data(locked("ca:" + ca_id, execute))

    @app.post("/api/v1/cas/<ca_id>/crl/resign")
    def crl_resign(ca_id):
        p = body_json()
        only(p, "bump_number", "next_update_hours", "confirm")
        if not bool_field(p, "confirm"):
            raise ApiError("CRL signing requires confirm=true")
        return json_data(locked("ca:" + ca_id, lambda: tool().resign_crl(
            ca_id, bump_number=bool_field(p, "bump_number", True),
            next_update_hours=int_field(p, "next_update_hours", None, minimum=1, maximum=8760))))

    @app.post("/api/v1/crls/resign-all")
    def crls_resign_all():
        p = body_json()
        only(p, "bump_number", "next_update_hours", "confirm")
        if not bool_field(p, "confirm"):
            raise ApiError("CRL signing requires confirm=true")
        return json_data(locked("all-crls", lambda: tool().resign_all_crls(
            bump_number=bool_field(p, "bump_number", True),
            next_update_hours=int_field(p, "next_update_hours", None, minimum=1, maximum=8760))))

    @app.post("/api/v1/cas/<ca_id>/ket")
    def ket_create(ca_id):
        p = body_json()
        only(p, "cn", "crt_path", "key_path", "rsa_bits", "valid_days", "confirm")
        if not bool_field(p, "confirm"):
            raise ApiError("KET creation requires confirm=true")
        opts = {"cn": text_field(p, "cn"),
                "crt_path": text_field(p, "crt_path", max_length=2048),
                "key_path": text_field(p, "key_path", max_length=2048),
                "rsa_bits": int_field(p, "rsa_bits", 4096, minimum=2048, maximum=16384),
                "valid_days": int_field(p, "valid_days", 3650, minimum=1, maximum=365000)}
        return json_data(locked("global-config", lambda: tool().create_ket(ca_id, **opts)), 201)

    @app.post("/api/v1/cas/<ca_id>/certificates/rotate")
    def cert_rotate(ca_id):
        p = body_json()
        only(p, "crt_path", "key_path", "threshold_days", "valid_days", "write_fullchain_to_crt", "confirm")
        if not bool_field(p, "confirm"):
            raise ApiError("Rotation requires confirm=true")
        args = {"crt_path": text_field(p, "crt_path", required=True, max_length=2048),
                "key_path": text_field(p, "key_path", required=True, max_length=2048),
                "threshold_days": int_field(p, "threshold_days", 30, minimum=0, maximum=365000),
                "valid_days": int_field(p, "valid_days", 365, minimum=1, maximum=365000),
                "write_fullchain_to_crt": bool_field(p, "write_fullchain_to_crt", True)}
        return json_data(locked("ca:" + ca_id, lambda: tool().rotate_certificate(ca_id, **args)))

    @app.post("/api/v1/cas/<ca_id>/csr")
    def csr_submit(ca_id):
        p = body_json()
        only(p, "csr_base64", "template_oid", "template_name", "confirm")
        if not bool_field(p, "confirm"):
            raise ApiError("CSR submission requires confirm=true")
        content = text_field(p, "csr_base64", required=True, max_length=1_500_000)
        try:
            csr_bytes = base64.b64decode(content, validate=True)
        except (ValueError, binascii.Error):
            raise ApiError("Invalid CSR base64")
        if not 1 <= len(csr_bytes) <= 1_000_000:
            raise ApiError("CSR must be 1 to 1000000 bytes")
        args = {"template_oid": text_field(p, "template_oid"),
                "template_name": text_field(p, "template_name")}
        if args["template_oid"] and args["template_name"]:
            raise ApiError("Choose one template selector")
        # Bind enrollment to the already authenticated web identity, not an
        # arbitrary username supplied by the caller.
        return json_data(locked("ca:" + ca_id, lambda: tool().submit_csr(
            ca_id, g.user, csr_bytes, **args)))

    @app.get("/api/v1/callbacks")
    def callbacks():
        return json_data(redact_config(tool().list_callbacks()))

    @app.get("/api/v1/config")
    def config_show():
        return json_data(redact_config(tool().show_config()))

    return app


# WSGI lazy loader: environment variables are required at startup (fail closed).
# This allows imports and mock-based tests without production settings.
def get_wsgi_app():
    return create_app()


if __name__ == "__main__":
    app = create_app()
    from waitress import serve
    serve(app, host=os.environ.get("ADCS_WEB_HOST", "127.0.0.1"),
          port=int(os.environ.get("ADCS_WEB_PORT", "8001")))
