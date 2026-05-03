import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_shared_renderer_writes_pdf_bytes(tmp_path):
    from cashel.html_pdf import render_html_to_pdf

    output = tmp_path / "report.pdf"
    render_html_to_pdf(
        "<!doctype html><html><body><h1>Cashel 2.0.0</h1></body></html>",
        str(output),
    )

    data = output.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 100


def test_renderer_raises_clear_error_when_chromium_fails(monkeypatch, tmp_path):
    import playwright.sync_api as sync_api
    from playwright.sync_api import Error as PlaywrightError

    import cashel.html_pdf as html_pdf

    class FakeChromium:
        def launch(self, *args, **kwargs):
            raise PlaywrightError("browser executable missing")

    class FakePlaywright:
        chromium = FakeChromium()

    class FakeContext:
        def __enter__(self):
            return FakePlaywright()

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(sync_api, "sync_playwright", lambda: FakeContext())

    with pytest.raises(html_pdf.PdfRendererUnavailable) as exc:
        html_pdf.render_html_to_pdf("<html><body>Cashel</body></html>", str(tmp_path / "x.pdf"))

    assert "python -m playwright install chromium" in str(exc.value)
