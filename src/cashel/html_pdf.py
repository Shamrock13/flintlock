"""HTML-to-PDF rendering helpers for Cashel reports."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


class PdfRendererUnavailable(RuntimeError):
    """Raised when Chromium/Playwright is not available for PDF rendering."""


_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(("html", "xml")),
)


def render_report_html(template_name: str, **context: Any) -> str:
    """Render a report template outside a Flask request context."""
    template = _ENV.get_template(template_name)
    return template.render(**context)


def render_html_to_pdf(
    html: str,
    output_path: str,
    *,
    page_format: str | None = None,
    timeout_ms: int | None = None,
) -> str:
    """Render HTML to a PDF file using Playwright/Chromium."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - exercised by explicit tests
        raise PdfRendererUnavailable(
            "Cashel PDF rendering requires Playwright. Install project dependencies "
            "and run `python -m playwright install chromium`."
        ) from exc

    page_format = page_format or os.environ.get("CASHEL_PDF_PAGE_FORMAT", "Letter")
    timeout_ms = timeout_ms or int(os.environ.get("CASHEL_PDF_TIMEOUT_MS", "30000"))

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page()
                page.set_content(html, wait_until="load", timeout=timeout_ms)
                page.emulate_media(media="print")
                page.pdf(
                    path=output_path,
                    format=page_format,
                    print_background=True,
                    margin={"top": "0", "right": "0", "bottom": "0", "left": "0"},
                    prefer_css_page_size=False,
                )
            finally:
                browser.close()
    except PlaywrightError as exc:
        raise PdfRendererUnavailable(
            "Cashel PDF rendering could not start Chromium. Run "
            "`python -m playwright install chromium` and try again."
        ) from exc

    return output_path


def render_template_to_pdf(template_name: str, output_path: str, **context: Any) -> str:
    """Render a Jinja report template to PDF with the shared Chromium engine."""
    html = render_report_html(template_name, **context)
    return render_html_to_pdf(html, output_path)
