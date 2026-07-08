"""Render selectable HTML report PDFs with local Chromium/Chrome."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


class ReportPdfError(RuntimeError):
    """Raised when a report PDF cannot be rendered."""


CHROME_CANDIDATE_PATHS = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]


def find_chromium_executable() -> str:
    env_path = os.getenv("FIRSTPROTOTYPE_CHROME_PATH")
    if env_path and Path(env_path).is_file():
        return env_path

    for candidate in CHROME_CANDIDATE_PATHS:
        if Path(candidate).is_file():
            return candidate

    raise ReportPdfError(
        "Chrome/Edge executable not found. Set FIRSTPROTOTYPE_CHROME_PATH to enable PDF export."
    )


def render_html_report_pdf(html: str) -> bytes:
    if not html or not html.strip():
        raise ReportPdfError("Report HTML is empty")

    chrome_path = find_chromium_executable()
    with tempfile.TemporaryDirectory(prefix="firstprototype-report-pdf-") as temp_dir:
        temp_path = Path(temp_dir)
        html_path = temp_path / "report.html"
        pdf_path = temp_path / "report.pdf"
        user_data_dir = temp_path / "chrome-profile"

        html_path.write_text(html, encoding="utf-8", newline="\n")

        command = [
            chrome_path,
            "--headless=new",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-gpu",
            "--disable-gpu-compositing",
            "--disable-dev-shm-usage",
            "--disable-features=VizDisplayCompositor",
            "--use-gl=swiftshader",
            "--hide-scrollbars",
            "--default-background-color=FFFFFFFF",
            "--no-first-run",
            "--no-default-browser-check",
            f"--user-data-dir={user_data_dir}",
            "--no-pdf-header-footer",
            f"--print-to-pdf={pdf_path}",
            html_path.as_uri(),
        ]

        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=45,
            )
        except subprocess.TimeoutExpired as exc:
            raise ReportPdfError("Timed out while rendering report PDF") from exc

        if completed.returncode != 0:
            error_text = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ReportPdfError(error_text or "Chrome failed to render report PDF")

        if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
            raise ReportPdfError("Chrome did not produce a report PDF")

        return pdf_path.read_bytes()
