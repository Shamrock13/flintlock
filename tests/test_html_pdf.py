import os
import sys
from pathlib import Path

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
        html_pdf.render_html_to_pdf(
            "<html><body>Cashel</body></html>", str(tmp_path / "x.pdf")
        )

    assert "python -m playwright install chromium" in str(exc.value)


def test_dockerfile_uses_preinstalled_playwright_headless_shell():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    body = dockerfile.read_text(encoding="utf-8")

    assert "ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in body
    assert "python -m playwright install --with-deps --only-shell chromium" in body
    assert "chown -R cashel:cashel /app /data /ms-playwright" in body
    assert "chmod -R a+rX /ms-playwright" in body
    assert "runtime" in body and "headless shell" in body


def test_modern_report_templates_render_html():
    from cashel.html_pdf import render_report_html
    from cashel.remediation import generate_plan
    from cashel.reporter import build_audit_report_context

    findings = [
        {
            "id": "CASHEL-ASA-ACL-001",
            "vendor": "asa",
            "severity": "HIGH",
            "category": "exposure",
            "title": "Unrestricted inbound ACL permit",
            "message": "[HIGH] permit ip any any",
            "evidence": "access-list OUTSIDE_IN extended permit ip any any",
            "affected_object": "OUTSIDE_IN",
            "impact": "Broad inbound exposure.",
            "remediation": "Replace with scoped permits.",
            "verification": "Re-run the audit.",
        }
    ]
    summary = {"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1, "score": 90}
    audit_context = build_audit_report_context(
        findings=findings,
        filename="edge.cfg",
        vendor="asa",
        compliance="cis",
        summary=summary,
    )
    plan = generate_plan(findings, "asa", "edge.cfg", "cis", summary)
    remediation_context = {
        "filename": plan["filename"],
        "vendor": plan["vendor"],
        "vendor_label": "Cisco",
        "compliance": "CIS Benchmark",
        "generated_date": "May 8, 2026",
        "generated_time": "12:00:00 UTC",
        "summary": summary,
        "total_steps": plan["total_steps"],
        "phases": [
            {
                **phase,
                "steps": [
                    {
                        **step,
                        "title": step.get("title") or "Remediation step",
                        "severity": str(step.get("severity", "HIGH")).title(),
                        "severity_key": str(step.get("severity", "HIGH")).lower(),
                        "effort_label": step.get("effort", "medium"),
                    }
                    for step in phase.get("steps", [])
                ],
            }
            for phase in plan["phases"]
        ],
        "disclaimer": plan.get("disclaimer", ""),
        "tool_version": "2.0.0",
    }
    cover_context = {
        "filename": "edge.cfg",
        "vendor": "asa",
        "vendor_label": "Cisco",
        "compliance": "CIS Benchmark",
        "summary": summary,
        "generated_date": "May 8, 2026",
        "generated_time": "12:00:00 UTC",
        "bundle_id": "bundle-test",
        "tool_version": "2.0.0",
        "items": ["audit_report.pdf - Full PDF audit report"],
    }

    rendered = [
        render_report_html("audit_report_pdf.html", report=audit_context),
        render_report_html("remediation_report_pdf.html", report=remediation_context),
        render_report_html("bundle_cover_pdf.html", cover=cover_context),
    ]

    assert all('<main class="paper">' in html for html in rendered)
    assert all("Cashel" in html for html in rendered)
