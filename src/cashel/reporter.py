from fpdf import FPDF
from datetime import datetime

# Brand colors (matching web light mode)
_NAVY = (30, 64, 128)  # #1E4080 header
_NAVY_DARK = (26, 26, 46)  # #1A1A2E dark accent
_WHITE = (255, 255, 255)
_LIGHT_BG = (245, 246, 251)  # page background tint
_BORDER = (208, 213, 234)  # card border
_TEXT = (26, 26, 46)  # body text
_MUTED = (107, 107, 138)  # secondary text

_CRITICAL = (204, 0, 0)  # #CC0000
_CRITICAL_BG = (255, 230, 230)
_HIGH = (204, 34, 0)  # #CC2200
_HIGH_BG = (255, 240, 238)
_MEDIUM = (153, 102, 0)  # #996600
_MEDIUM_BG = (255, 248, 230)
_COMP = (26, 85, 204)  # #1A55CC compliance blue
_COMP_BG = (235, 242, 255)
_PASS = (26, 128, 85)  # #1A8055
_PASS_BG = (235, 250, 244)


def _sanitize(text: str) -> str:
    """Replace Unicode characters that fall outside Latin-1 with ASCII equivalents.
    Required because fpdf2 core fonts (Courier, Helvetica) only support cp1252/Latin-1."""
    _MAP = {
        "\u2014": "-",  # em dash
        "\u2013": "-",  # en dash
        "\u2192": "->",  # right arrow
        "\u2190": "<-",  # left arrow
        "\u2022": "*",  # bullet
        "\u2026": "...",  # ellipsis
        "\u201c": '"',  # left double quote
        "\u201d": '"',  # right double quote
        "\u2018": "'",  # left single quote
        "\u2019": "'",  # right single quote
        "\u2713": "OK",  # checkmark
        "\u2718": "X",  # cross mark
    }
    for char, replacement in _MAP.items():
        text = text.replace(char, replacement)
    # Final fallback: drop anything still outside Latin-1
    return text.encode("latin-1", errors="replace").decode("latin-1")


VENDOR_DISPLAY = {
    "asa": "Cisco",
    "paloalto": "Palo Alto Networks",
    "fortinet": "Fortinet",
    "pfsense": "pfSense",
    "aws": "AWS Security Group",
    "azure": "Azure NSG",
}


class CashelReport(FPDF):
    def header(self):
        # Navy header bar
        self.set_fill_color(*_NAVY)
        self.rect(0, 0, 210, 30, "F")

        # Logo / title
        self.set_text_color(*_WHITE)
        self.set_font("Helvetica", "B", 17)
        self.set_xy(12, 8)
        self.cell(120, 9, "Cashel")

        # Subtitle
        self.set_font("Helvetica", "", 8)
        self.set_text_color(180, 200, 235)
        self.set_xy(12, 19)
        self.cell(120, 6, "Firewall Security Report")

        # Date — right-aligned
        self.set_font("Helvetica", "", 8)
        self.set_text_color(180, 200, 235)
        self.set_xy(0, 19)
        self.cell(
            198,
            6,
            f"Generated: {datetime.now().strftime('%Y-%m-%d  %H:%M')}",
            align="R",
        )

        # Thin accent stripe at base of header
        self.set_fill_color(233, 69, 96)
        self.rect(0, 29.5, 210, 0.6, "F")

        self.set_y(36)

    def footer(self):
        self.set_y(-13)
        self.set_draw_color(*_BORDER)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*_MUTED)
        self.cell(
            0,
            5,
            f"Cashel v1.1   |   Firewall Security Auditor   |   Page {self.page_no()}",
            align="C",
        )


def _draw_meta(pdf, filename, vendor, compliance):
    """Render file/vendor/framework info bar."""
    pdf.set_fill_color(*_LIGHT_BG)
    y = pdf.get_y()
    pdf.rect(10, y, 190, 10, "F")

    vendor_name = VENDOR_DISPLAY.get(vendor, vendor.upper())
    framework = compliance.upper() if compliance else "None"
    meta = f"File: {filename}   |   Vendor: {vendor_name}   |   Framework: {framework}"

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*_MUTED)
    pdf.set_xy(13, y + 2)
    pdf.cell(184, 6, _sanitize(meta))
    pdf.set_y(y + 13)


def _draw_summary_boxes(pdf, high, medium, total, score=None, critical=0):
    """Summary boxes side by side — Critical / High / Medium / Total / Score."""
    _SCORE_GREEN = (26, 128, 85)
    _SCORE_GREEN_BG = (235, 250, 244)
    _SCORE_AMBER = (153, 102, 0)
    _SCORE_AMBER_BG = (255, 248, 230)
    _SCORE_RED = (204, 34, 0)
    _SCORE_RED_BG = (255, 240, 238)

    if score is not None:
        sc, sb = (
            (_SCORE_GREEN, _SCORE_GREEN_BG)
            if score >= 80
            else (_SCORE_AMBER, _SCORE_AMBER_BG)
            if score >= 50
            else (_SCORE_RED, _SCORE_RED_BG)
        )
        box_w, box_h = 34, 24
        positions = [10, 48, 86, 124, 162]
        styles = [
            (_CRITICAL_BG, _CRITICAL, _CRITICAL, str(critical), "Critical"),
            (_HIGH_BG, _HIGH, _HIGH, str(high), "High"),
            (_MEDIUM_BG, _MEDIUM, _MEDIUM, str(medium), "Medium"),
            (_LIGHT_BG, _BORDER, _NAVY, str(total), "Total"),
            (sb, sc, sc, str(score) + "/100", "Score"),
        ]
    else:
        box_w, box_h = 43, 24
        positions = [10, 57, 104, 151]
        styles = [
            (_CRITICAL_BG, _CRITICAL, _CRITICAL, str(critical), "Critical"),
            (_HIGH_BG, _HIGH, _HIGH, str(high), "High"),
            (_MEDIUM_BG, _MEDIUM, _MEDIUM, str(medium), "Medium"),
            (_LIGHT_BG, _BORDER, _NAVY, str(total), "Total"),
        ]
    y = pdf.get_y()

    for x, (fill, draw, text, val, lbl) in zip(positions, styles):
        pdf.set_fill_color(*fill)
        pdf.set_draw_color(*draw)
        pdf.set_line_width(0.4)
        pdf.rect(x, y, box_w, box_h, "FD")

        pdf.set_text_color(*text)
        pdf.set_font("Helvetica", "B", 16 if score is not None else 20)
        pdf.set_xy(x, y + 3)
        pdf.cell(box_w, 10, val, align="C")

        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_xy(x, y + 15)
        pdf.cell(box_w, 6, lbl, align="C")

    pdf.set_y(y + box_h + 8)


def _section_header(pdf, title, color):
    """Colored left-accent bar + section title."""
    y = pdf.get_y()
    # Left accent bar
    pdf.set_fill_color(*color)
    pdf.rect(10, y, 3, 7, "F")
    # Title text
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(*color)
    pdf.set_xy(15, y)
    pdf.cell(0, 7, _sanitize(title))
    pdf.ln(9)


_CATEGORY_COLORS = {
    "exposure": (204, 34, 0),
    "logging": (153, 102, 0),
    "protocol": (170, 68, 255),
    "hygiene": (26, 85, 204),
    "redundancy": (107, 107, 138),
    "compliance": (26, 85, 204),
}


def _draw_finding(
    pdf, finding, bar_color, bg_color, text_color, category=None, remediation=None
):
    """Single finding row with colored left bar, optional category prefix and remediation."""
    x, w = 10, 190
    bar_w = 3
    inner_w = w - bar_w - 4

    # Estimate heights
    pdf.set_font("Courier", "", 7.5)
    char_per_line = int(inner_w / 2.3)
    msg_text = finding if isinstance(finding, str) else str(finding)
    lines = max(1, (len(msg_text) + char_per_line - 1) // char_per_line)
    row_h = max(9, lines * 4.5 + 3)
    if remediation:
        rem_chars = int(inner_w / 2.0)
        rem_lines = max(1, (len(remediation) + rem_chars - 1) // rem_chars)
        row_h += rem_lines * 3.8 + 2

    y = pdf.get_y()
    if y + row_h > 272:
        pdf.add_page()
        y = pdf.get_y()

    # Accent bar
    pdf.set_fill_color(*bar_color)
    pdf.rect(x, y, bar_w, row_h, "F")

    # Row background
    pdf.set_fill_color(*bg_color)
    pdf.rect(x + bar_w, y, w - bar_w, row_h, "F")

    cur_y = y + 1.5

    # Category label (colored text prefix)
    if category:
        cat_color = _CATEGORY_COLORS.get(category, text_color)
        pdf.set_text_color(*cat_color)
        pdf.set_font("Helvetica", "B", 6.5)
        cat_label = "[" + category.upper() + "]  "
        pdf.set_xy(x + bar_w + 2, cur_y)
        pdf.cell(inner_w, 4, cat_label)
        cur_y += 4

    # Finding message
    pdf.set_text_color(*text_color)
    pdf.set_font("Courier", "", 7.5)
    pdf.set_xy(x + bar_w + 2, cur_y)
    pdf.multi_cell(inner_w, 4.5, _sanitize(msg_text))
    cur_y = pdf.get_y()

    # Remediation text (indented, smaller, muted)
    if remediation:
        pdf.set_text_color(*_MUTED)
        pdf.set_font("Helvetica", "", 6.5)
        pdf.set_xy(x + bar_w + 6, cur_y + 0.5)
        pdf.multi_cell(inner_w - 4, 3.8, _sanitize("-> " + remediation))

    pdf.set_y(y + row_h + 1)


def _findings_group(pdf, title, findings, bar_color, bg_color, text_color):
    if not findings:
        return
    _section_header(pdf, title, bar_color)
    for f in findings:
        if isinstance(f, dict):
            _draw_finding(
                pdf,
                f["message"],
                bar_color,
                bg_color,
                text_color,
                category=f.get("category"),
                remediation=f.get("remediation"),
            )
        else:
            _draw_finding(pdf, f, bar_color, bg_color, text_color)
    pdf.ln(4)


def generate_report(
    findings, filename, vendor, compliance=None, output_path="report.pdf", summary=None
):
    # Normalize: accept both string findings and dict findings; keep dicts for display
    def _msg(f):
        return f["message"] if isinstance(f, dict) else f

    # Build grouped lists — preserve dicts so category/remediation info is available
    def _contains(f, tag):
        return tag in _msg(f)

    critical = [
        f
        for f in findings
        if _contains(f, "[CRITICAL]")
        and not any(_contains(f, x) for x in ("PCI-", "CIS-", "NIST-"))
    ]
    high = [
        f
        for f in findings
        if _contains(f, "[HIGH]")
        and not any(_contains(f, x) for x in ("PCI-", "CIS-", "NIST-"))
    ]
    medium = [
        f
        for f in findings
        if _contains(f, "[MEDIUM]")
        and not any(_contains(f, x) for x in ("PCI-", "CIS-", "NIST-"))
    ]
    pci_h = [f for f in findings if _contains(f, "PCI-HIGH")]
    pci_m = [f for f in findings if _contains(f, "PCI-MEDIUM")]
    cis_h = [f for f in findings if _contains(f, "CIS-HIGH")]
    cis_m = [f for f in findings if _contains(f, "CIS-MEDIUM")]
    nist_h = [f for f in findings if _contains(f, "NIST-HIGH")]
    nist_m = [f for f in findings if _contains(f, "NIST-MEDIUM")]

    total_critical = len(critical)
    total_high = len(high) + len(pci_h) + len(cis_h) + len(nist_h)
    total_medium = len(medium) + len(pci_m) + len(cis_m) + len(nist_m)

    score = summary.get("score") if isinstance(summary, dict) else None

    pdf = CashelReport()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    _draw_meta(pdf, filename, vendor, compliance)
    _draw_summary_boxes(pdf, total_high, total_medium, len(findings), score=score, critical=total_critical)

    # Divider
    pdf.set_draw_color(*_BORDER)
    pdf.set_line_width(0.3)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    if not findings:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*_PASS)
        pdf.cell(0, 8, "[PASS]  No issues found", align="C")
    else:
        _findings_group(pdf, "High Severity", high, _HIGH, _HIGH_BG, _HIGH)
        _findings_group(pdf, "Medium Severity", medium, _MEDIUM, _MEDIUM_BG, _MEDIUM)
        if pci_h or pci_m:
            _findings_group(pdf, "PCI Compliance — High", pci_h, _COMP, _COMP_BG, _COMP)
            _findings_group(
                pdf, "PCI Compliance — Medium", pci_m, _COMP, _COMP_BG, _COMP
            )
        if cis_h or cis_m:
            _findings_group(pdf, "CIS Compliance — High", cis_h, _COMP, _COMP_BG, _COMP)
            _findings_group(
                pdf, "CIS Compliance — Medium", cis_m, _COMP, _COMP_BG, _COMP
            )
        if nist_h or nist_m:
            _findings_group(
                pdf, "NIST Compliance — High", nist_h, _COMP, _COMP_BG, _COMP
            )
            _findings_group(
                pdf, "NIST Compliance — Medium", nist_m, _COMP, _COMP_BG, _COMP
            )

    pdf.output(output_path)
    return output_path
