import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from xml.sax.saxutils import escape

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from tools.build_linux_apt_2024_dataset import build_linux_apt_2024_dataset  # noqa: E402


def _write_minimal_xlsx(path: Path) -> None:
    shared = [
        "timestamp",
        "agent\\.name",
        "full_log",
        "rule\\.description",
        "rule\\.mitre\\.tactic",
        "rule\\.mitre\\.technique",
        "rule\\.mitre\\.id",
        "Malicious / General",
        "Oct 5, 2023 @ 20:21:46.060",
        "machine-1",
        '192.168.204.1 - - [06/Oct/2023:01:21:44 +0500] "GET /DVWA/vulnerabilities/xss_r/?name=<script>alert(1)</script> HTTP/1.1" 302 342 "-" "curl"',
        "Common web attack.",
        "InitialAccess",
        "Exploit Public-Facing Application",
        '["T1190"]',
        "1",
        "Oct 5, 2023 @ 19:46:51.957",
        "ubuntu",
        "ossec: Manager started.",
        "Wazuh server started.",
        "",
        "0",
    ]
    shared_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        f'count="{len(shared)}" uniqueCount="{len(shared)}">'
        + "".join(f"<si><t>{escape(item)}</t></si>" for item in shared)
        + "</sst>"
    )
    sheet_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c>
      <c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>3</v></c>
      <c r="E1" t="s"><v>4</v></c><c r="F1" t="s"><v>5</v></c>
      <c r="G1" t="s"><v>6</v></c><c r="L1" t="s"><v>7</v></c>
    </row>
    <row r="2">
      <c r="A2" t="s"><v>8</v></c><c r="B2" t="s"><v>9</v></c>
      <c r="C2" t="s"><v>10</v></c><c r="D2" t="s"><v>11</v></c>
      <c r="E2" t="s"><v>12</v></c><c r="F2" t="s"><v>13</v></c>
      <c r="G2" t="s"><v>14</v></c><c r="L2" t="s"><v>15</v></c>
    </row>
    <row r="3">
      <c r="A3" t="s"><v>16</v></c><c r="B3" t="s"><v>17</v></c>
      <c r="C3" t="s"><v>18</v></c><c r="D3" t="s"><v>19</v></c>
      <c r="E3" t="s"><v>20</v></c><c r="F3" t="s"><v>20</v></c>
      <c r="G3" t="s"><v>20</v></c><c r="L3" t="s"><v>21</v></c>
    </row>
  </sheetData>
</worksheet>
"""
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "")
        archive.writestr("xl/workbook.xml", "")
        archive.writestr("xl/sharedStrings.xml", shared_xml)
        archive.writestr("xl/worksheets/sheet1.xml", sheet_xml)


class LinuxApt2024DatasetBuilderTest(unittest.TestCase):
    def test_build_linux_apt_2024_dataset_reads_xlsx_labels_without_mitre_leakage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            xlsx_path = root / "Processed Version.xlsx"
            _write_minimal_xlsx(xlsx_path)

            summary = build_linux_apt_2024_dataset(
                input_xlsx=xlsx_path,
                output_dir=root / "out",
                log_name="linux_apt_2024.log",
            )
            written = pd.read_csv(root / "out" / "linux_apt_2024.log_structured.csv")

            self.assertEqual(summary["rows"], 2)
            self.assertEqual(summary["label_counts"], {"attack": 1, "-": 1})
            self.assertEqual(written["AgentName"].tolist(), ["machine-1", "ubuntu"])
            self.assertEqual(written["Label"].tolist(), ["attack", "-"])
            self.assertTrue((written["Timestamp"] > 0).all())
            self.assertIn("AptApache method=GET status=302 action=xss_probe", written["EventTemplate"].tolist())
            self.assertNotIn("InitialAccess", "|".join(written["EventTemplate"].astype(str)))
            self.assertNotIn("Exploit Public-Facing Application", "|".join(written["EventTemplate"].astype(str)))
            self.assertIn("EventId", written.columns)


if __name__ == "__main__":
    unittest.main()
