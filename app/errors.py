"""Error visibility (P12): log context without secrets, readable 500s.

* RedactSecretsFilter - attached to every log handler; scrubs the literal
  values of secret-looking environment variables and `key=value` pairs
  (password/secret/token/webhook) from anything that is about to be
  written, so a stray `log.debug(os.environ)` or an exception message can
  never leak a credential. Applies to tracker.log AND the console/service
  log.
* install_error_handlers - unhandled exceptions become a short, readable
  page with a correlation id, while the full traceback (request path, user,
  method - but never request bodies) goes to the log.
"""
from __future__ import annotations

import logging
import os
import re
import secrets as _secrets

log = logging.getLogger("tracker.errors")

_SECRET_KEY_RE = re.compile(r"SECRET|PASSWORD|PASSPHRASE|TOKEN|WEBHOOK", re.I)
# Key names as they appear inside JSON, SQL, dict reprs and headers:
# `"password": x`, 'password_hash': x, session_secret=x, Api-Key: x.
# The optional quote between key and separator is what the old pattern
# lacked - without it every quoted key slipped past - and names like
# access_token never matched because `_` sits where a word boundary was
# required.
_KV_KEYS = (
    "password_hash|password|passwd|passphrase|"
    "session_secret|client_secret|secret_key|secret|"
    "access_token|refresh_token|id_token|auth_token|token|"
    "api[_-]?key|webhook_url|webhook|authorization"
)
_KV_RE = re.compile(
    rf"""(?i)(?P<key>{_KV_KEYS})(?P<q>['"]?)\s*(?P<sep>[=:])\s*"""
    rf"""(?P<vq>[\x27\x22]?)(?P<val>[^\s,;\x29\x27\x22\x5d]+)(?P<eq>[\x27\x22]?)""")
# `Authorization: Bearer eyJ...` carries no key=value pair of its own, so
# it needs its own pattern; _scrub runs this first, then _KV_RE redacts the
# `Authorization:` value as well.
_BEARER_RE = re.compile(r"""(?i)\bbearer\s+(?P<tok>[^\s,;\x29\x27\x22\x5d]+)""")
REDACTED = "***REDACTED***"

# Applied to every response class: normal pages via the session middleware
# in main.py, error responses via install_error_handlers (which runs
# outside that middleware).
# CSP rationale: same-origin only, no framing, no referrer leakage. No
# template ships inline <script> (users.html's confirm uses data-confirm)
# so script-src can stay strict; style-src stays unsafe-inline because
# generated incident reports embed a <style> block.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' "
        "'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"),
}


def apply_security_headers(response) -> None:
    """setdefault, so a route that sets a stricter value keeps it."""
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)


def _secret_values() -> list[str]:
    vals = []
    for key, value in os.environ.items():
        if len(value) >= 6 and _SECRET_KEY_RE.search(key):
            vals.append(value)
    return vals


class RedactSecretsFilter(logging.Filter):
    """Scrubs secret values from records - message AND traceback text -
    before they are formatted."""

    @staticmethod
    def _scrub(text: str) -> str:
        redacted = text
        for value in _secret_values():
            if value in redacted:
                redacted = redacted.replace(value, REDACTED)
        redacted = _BEARER_RE.sub(f"Bearer {REDACTED}", redacted)
        return _KV_RE.sub(lambda m: f"{m.group('key')}={REDACTED}", redacted)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = self._scrub(record.getMessage())
            if msg != record.getMessage():
                record.msg = msg
                record.args = ()
            # tracebacks carry source lines (which may embed literals from
            # an f-string or repr) - scrub them the same way
            if record.exc_info and not record.exc_text:
                import traceback
                try:
                    record.exc_text = "".join(
                        traceback.format_exception(*record.exc_info))
                except Exception:  # noqa: BLE001
                    record.exc_text = ""
            if record.exc_text:
                record.exc_text = self._scrub(record.exc_text)
        except Exception:  # noqa: BLE001 - filtering must never break logging
            record.msg = "<log record could not be formatted>"
            record.args = ()
        return True


_factory_installed = False


def install_record_redaction() -> None:
    """Scrub every record at creation time, so ALL sinks - tracker.log, the
    console/service log, third-party handlers and test capture - receive
    redacted data regardless of handler order or per-handler filters."""
    global _factory_installed
    if _factory_installed:
        return
    previous = logging.getLogRecordFactory()
    scrubber = RedactSecretsFilter()

    def factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        scrubber.filter(record)
        return record

    logging.setLogRecordFactory(factory)
    _factory_installed = True


def install_error_handlers(app) -> None:
    """Replace the default 500 with a readable page + rich server log."""
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, PlainTextResponse

    async def server_error(request: Request, exc: Exception) -> object:
        correlation = _secrets.token_hex(4)
        user = getattr(request.state, "user", None)
        log.exception(
            "unhandled error %s during %s %s (user=%s, correlation=%s)",
            type(exc).__name__, request.method, request.url.path,
            user.get("username") if user else "anonymous", correlation)
        accept = request.headers.get("accept", "")
        detail = (f"Something went wrong while handling this request.\n"
                  f"Correlation id: {correlation}\n"
                  f"The full error is in logs\\tracker.log "
                  f"(search for the correlation id).")
        if "text/html" in accept:
            body = (
                "<!doctype html><title>Server error</title>"
                "<style>body{font-family:system-ui,sans-serif;margin:3rem;"
                "max-width:40rem}code{background:#eee;padding:.2rem .4rem}"
                "</style><h1>Something went wrong</h1><p>The request could "
                "not be completed. This page deliberately hides technical "
                "details; the full error is in the log file.</p>"
                f"<p>Correlation id: <code>{correlation}</code></p>"
                "<p>Check <code>logs\\tracker.log</code> (and "
                "<code>logs\\service.err.log</code> when running as a "
                "service), then reload the page.</p>")
            response = HTMLResponse(body, status_code=500)
        else:
            response = PlainTextResponse(detail, status_code=500)
        # ServerErrorMiddleware sits OUTSIDE the session middleware, so this
        # response never passes through it - without this, every 500 page
        # (and the plain-text 500) shipped with no security headers at all.
        apply_security_headers(response)
        return response

    app.add_exception_handler(500, server_error)
    app.add_exception_handler(Exception, server_error)
