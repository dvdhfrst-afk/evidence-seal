"""A local web interface and JSON API for the seal library: ``evidence-seal serve``.

Modules: server (listening and the checks on every request), security (keys, sessions, headers),
routing, inputs (form fields and typed paths), multipart (upload parsing), jobs (background work),
actions (what pages and the API do), pages (HTML), api (JSON under /api/v1/), markup, assets and
command (the serve command). docs/WEB.md describes the pages, the API and the security model.
"""

from __future__ import annotations

from .command import register

__all__ = ["register"]
