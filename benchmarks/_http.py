"""One outbound POST for every model call in `benchmarks/`, with no redirects.

WHY THIS EXISTS
---------------
Five modules here POST to a model endpoint with a credential in the header:
`compile_ontology`, `compile_roles`, `plan_sets`, `llm_monitor` and
`openai_ask`. Each built its own `urllib.request.urlopen` call, and each pinned
`https://` before constructing the URL, which is the right check and not a
sufficient one.

`urlopen` follows 3xx by default, and CPython's `HTTPRedirectHandler` copies the
ORIGINAL request headers onto the redirect target. So a 302 from the configured
endpoint to `http://elsewhere/` re-sends `api-key` or `Authorization: Bearer` in
cleartext to a host nobody configured. The https pin does not help: it validated
the first URL, not the one the credential actually reached.

`clayseal/core/safe_http.py` has said "No redirects" in its module docstring
since it was written. These call sites simply were not routed through anything
that enforced it.

WHY REFUSING IS RIGHT, RATHER THAN STRIPPING HEADERS
-----------------------------------------------------
A chat-completions API does not legitimately redirect a POST. Stripping the auth
header on a cross-origin hop would turn a redirect into a confusing 401 from an
unexpected host; refusing turns it into an error that names the problem. The
narrower behaviour is also the one that cannot be got wrong later by someone
adding a header the strip list does not know about.

Not a general-purpose client. It does one thing: POST JSON to an https URL and
return the body, refusing anything that would move the credential somewhere the
caller did not name.
"""
from __future__ import annotations

import urllib.error
import urllib.request

__all__ = ["RedirectRefused", "post_json"]


class RedirectRefused(urllib.error.URLError):
    """The endpoint tried to redirect a credentialed POST."""

    def __init__(self, code: int, location: str) -> None:
        super().__init__(
            f"endpoint returned HTTP {code} redirecting to {location!r}; "
            f"refusing to forward the API key. A chat-completions endpoint "
            f"does not legitimately redirect a POST, so this is either a "
            f"misconfigured endpoint or an attempt to capture the credential."
        )
        self.code, self.location = code, location


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect rather than re-sending the auth header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RedirectRefused(code, newurl)


#: Built once. `urlopen` uses a module-global opener that other code may have
#: installed, so this takes its own rather than depending on global state.
_OPENER = urllib.request.build_opener(_NoRedirect)


def post_json(url: str, *, data: bytes, headers: dict[str, str], timeout: float):
    """POST `data` to an https `url`. Returns the response object.

    Raises RuntimeError if the URL is not https, so the check cannot be skipped
    by a caller that forgot it, and RedirectRefused on any 3xx.
    """
    if not url.startswith("https://"):
        raise RuntimeError(f"refusing to send a credential over non-https: {url!r}")
    # Scheme is pinned to https immediately above, which is what S310 asks for,
    # and the opener refuses redirects so it cannot be moved off https later.
    req = urllib.request.Request(url, data=data, headers=headers)  # noqa: S310
    return _OPENER.open(req, timeout=timeout)
